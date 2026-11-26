import type { RawFinding, Severity } from '../../core/types.js';
import type { RepoIndex } from '../../repo/index.js';
import { readTextFile } from '../../repo/read.js';

async function read(index: RepoIndex, path: string): Promise<string | null> {
  try {
    return (await readTextFile(index.inventory.root, path, { maxBytes: 400_000 })).text;
  } catch {
    return null;
  }
}

function clip(line: string): string {
  const t = line.trim();
  return t.length > 160 ? `${t.slice(0, 160)}…` : t;
}

interface Init {
  rule: string;
  kb: string;
  title: string;
  severity: Severity;
  target: string;
  line?: number;
  evidence: string;
  confidence?: 'high' | 'medium' | 'low';
  verified?: boolean;
  category?: string;
}

function f(i: Init): RawFinding {
  return {
    rule: i.rule,
    kb: i.kb,
    title: i.title,
    severity: i.severity,
    confidence: i.confidence ?? 'high',
    domain: 'config',
    category: i.category ?? 'infrastructure',
    target: i.target,
    ...(i.line !== undefined ? { line: i.line } : {}),
    evidence: i.evidence,
    verified: i.verified ?? false,
    verification: i.verified
      ? 'Observed directly in the file.'
      : 'Pattern match on the configuration text; the deployed environment was not inspected.',
  };
}

export async function configFindings(index: RepoIndex): Promise<RawFinding[]> {
  const out: RawFinding[] = [];
  const paths = index.inventory.files.map((x) => x.path);

  for (const file of paths.filter((p) => /(^|\/)Dockerfile[\w.-]*$/.test(p))) {
    const text = await read(index, file);
    if (text === null) continue;
    const lines = text.split(/\r?\n/);
    const froms = lines.map((l, i) => ({ l, n: i + 1 })).filter((x) => /^\s*FROM\s/i.test(x.l));
    for (const x of froms) {
      const image = x.l.replace(/^\s*FROM\s+(--platform=\S+\s+)?/i, '').split(/\s+/)[0] ?? '';
      if (image.toLowerCase() === 'scratch' || image.startsWith('$') || image.includes('@sha256:'))
        continue;
      if (!image.includes(':') || /:latest$/.test(image)) {
        out.push(
          f({
            rule: 'CFG-DKR-001',
            kb: 'docker-unpinned',
            title: 'Docker base image is not pinned',
            severity: 'low',
            target: file,
            line: x.n,
            evidence: clip(x.l),
            verified: true,
            category: 'supply-chain',
          }),
        );
      }
    }
    const lastFrom = froms.at(-1)?.n ?? 0;
    const nonRoot = lines.slice(lastFrom).some((l) => /^\s*USER\s+(?!root\b|0\b)\S+/i.test(l));
    if (froms.length > 0 && !nonRoot) {
      out.push(
        f({
          rule: 'CFG-DKR-002',
          kb: 'docker-root',
          title: 'Container runs as root',
          severity: 'medium',
          target: file,
          evidence: 'No non-root USER instruction in the final build stage',
          confidence: 'medium',
          verified: true,
        }),
      );
    }
    lines.forEach((l, i) => {
      if (
        /^\s*(ENV|ARG)\s+\w*(PASSWORD|SECRET|TOKEN|API_?KEY)\w*[= ]\s*(?!\$)[^\s$]{6,}/i.test(l)
      ) {
        out.push(
          f({
            rule: 'CFG-DKR-003',
            kb: 'docker-secret-layer',
            title: 'Secret-like value baked into an image layer',
            severity: 'high',
            target: file,
            line: i + 1,
            evidence: clip(l.replace(/([= ])[^\s$]{6,}\s*$/, '$1<hidden>')),
            confidence: 'medium',
            category: 'secrets',
          }),
        );
      }
      if (/^\s*ADD\s+https?:\/\//i.test(l)) {
        out.push(
          f({
            rule: 'CFG-DKR-004',
            kb: 'docker-add-remote',
            title: 'Dockerfile ADD downloads a remote URL',
            severity: 'low',
            target: file,
            line: i + 1,
            evidence: clip(l),
            category: 'supply-chain',
          }),
        );
      }
      if (/^\s*EXPOSE\s+(22|23|3389)\b/.test(l)) {
        out.push(
          f({
            rule: 'CFG-DKR-005',
            kb: 'docker-remote-access-port',
            title: 'Container exposes a remote-administration port',
            severity: 'medium',
            target: file,
            line: i + 1,
            evidence: clip(l),
            confidence: 'medium',
          }),
        );
      }
    });
  }

  for (const file of paths.filter((p) => /(^|\/)(docker-)?compose[\w.-]*\.ya?ml$/.test(p))) {
    const text = await read(index, file);
    if (text === null) continue;
    text.split(/\r?\n/).forEach((l, i) => {
      if (/^\s*privileged:\s*true\b/.test(l))
        out.push(
          f({
            rule: 'CFG-DKR-006',
            kb: 'container-privileged',
            title: 'Privileged container',
            severity: 'high',
            target: file,
            line: i + 1,
            evidence: clip(l),
            verified: true,
          }),
        );
      if (
        /^\s*-\s*["']?(?:0\.0\.0\.0:)?(5432|3306|27017|6379|9200|11211|5984|2375):\1["']?\s*$/.test(
          l,
        )
      )
        out.push(
          f({
            rule: 'CFG-DKR-007',
            kb: 'compose-published-db',
            title: 'Database or admin port published on all interfaces',
            severity: 'medium',
            target: file,
            line: i + 1,
            evidence: clip(l),
            confidence: 'medium',
          }),
        );
      if (/^\s*-\s*\/var\/run\/docker\.sock/.test(l))
        out.push(
          f({
            rule: 'CFG-DKR-008',
            kb: 'docker-socket',
            title: 'Docker socket mounted into a container',
            severity: 'high',
            target: file,
            line: i + 1,
            evidence: clip(l),
            verified: true,
          }),
        );
      if (/^\s*network_mode:\s*["']?host/.test(l))
        out.push(
          f({
            rule: 'CFG-DKR-009',
            kb: 'container-privileged',
            title: 'Container uses the host network',
            severity: 'medium',
            target: file,
            line: i + 1,
            evidence: clip(l),
            verified: true,
          }),
        );
      if (
        /^\s*-?\s*\w*(PASSWORD|SECRET|TOKEN|API_?KEY)\w*\s*[:=]\s*["']?(?!\$)[^\s"'$]{6,}/i.test(
          l,
        ) &&
        !/(change|example|your|xxx|<)/i.test(l)
      )
        out.push(
          f({
            rule: 'CFG-DKR-010',
            kb: 'hardcoded-secret',
            title: 'Secret-like value hard-coded in compose file',
            severity: 'medium',
            target: file,
            line: i + 1,
            evidence: clip(l.replace(/([:=]\s*["']?)[^\s"']{6,}/, '$1<hidden>')),
            confidence: 'medium',
            category: 'secrets',
          }),
        );
    });
  }

  // Kubernetes manifests: YAML containing apiVersion and kind.
  for (const file of paths.filter((p) => /\.ya?ml$/i.test(p) && !/^\.github\//.test(p))) {
    const text = await read(index, file);
    if (
      text === null ||
      !/^\s*apiVersion:/m.test(text) ||
      !/^\s*kind:\s*(Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|ReplicaSet)\b/m.test(text)
    )
      continue;
    const lines = text.split(/\r?\n/);
    const find = (re: RegExp): number => lines.findIndex((l) => re.test(l)) + 1;
    const checks: Array<[RegExp, Init]> = [
      [
        /^\s*privileged:\s*true\b/,
        {
          rule: 'CFG-K8S-001',
          kb: 'container-privileged',
          title: 'Kubernetes container runs privileged',
          severity: 'high',
          target: file,
          evidence: 'securityContext.privileged: true',
          verified: true,
        },
      ],
      [
        /^\s*hostNetwork:\s*true\b/,
        {
          rule: 'CFG-K8S-002',
          kb: 'k8s-host-namespace',
          title: 'Pod shares the host network namespace',
          severity: 'medium',
          target: file,
          evidence: 'hostNetwork: true',
          verified: true,
        },
      ],
      [
        /^\s*hostPID:\s*true\b|^\s*hostIPC:\s*true\b/,
        {
          rule: 'CFG-K8S-003',
          kb: 'k8s-host-namespace',
          title: 'Pod shares the host PID or IPC namespace',
          severity: 'high',
          target: file,
          evidence: 'hostPID/hostIPC: true',
          verified: true,
        },
      ],
      [
        /^\s*allowPrivilegeEscalation:\s*true\b/,
        {
          rule: 'CFG-K8S-004',
          kb: 'k8s-security-context',
          title: 'Privilege escalation allowed in container',
          severity: 'medium',
          target: file,
          evidence: 'allowPrivilegeEscalation: true',
          verified: true,
        },
      ],
      [
        /^\s*runAsUser:\s*0\b/,
        {
          rule: 'CFG-K8S-005',
          kb: 'k8s-security-context',
          title: 'Container runs as UID 0 (root)',
          severity: 'medium',
          target: file,
          evidence: 'runAsUser: 0',
          verified: true,
        },
      ],
      [
        /^\s*image:\s*\S+:latest\s*$|^\s*image:\s*[^:\s@]+\s*$/,
        {
          rule: 'CFG-K8S-006',
          kb: 'docker-unpinned',
          title: 'Container image not pinned to a version',
          severity: 'low',
          target: file,
          evidence: 'image uses :latest or has no tag',
          category: 'supply-chain',
        },
      ],
      [
        /^\s*path:\s*\/var\/run\/docker\.sock/,
        {
          rule: 'CFG-K8S-007',
          kb: 'docker-socket',
          title: 'Docker socket mounted into a pod',
          severity: 'high',
          target: file,
          evidence: 'hostPath /var/run/docker.sock',
          verified: true,
        },
      ],
    ];
    for (const [re, init] of checks) {
      const n = find(re);
      if (n > 0)
        out.push(
          f({ ...init, line: n, evidence: `${init.evidence}: ${clip(lines[n - 1] ?? '')}` }),
        );
    }
    if (!/readOnlyRootFilesystem:\s*true/.test(text) && !/securityContext:/.test(text)) {
      out.push(
        f({
          rule: 'CFG-K8S-008',
          kb: 'k8s-security-context',
          title: 'Workload has no securityContext',
          severity: 'low',
          target: file,
          evidence:
            'No securityContext (runAsNonRoot, readOnlyRootFilesystem, dropped capabilities) was found',
          confidence: 'medium',
        }),
      );
    }
  }

  // Terraform.
  for (const file of paths.filter((p) => /\.tf$/i.test(p))) {
    const text = await read(index, file);
    if (text === null) continue;
    text.split(/\r?\n/).forEach((l, i) => {
      const n = i + 1;
      if (/cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\]/.test(l)) {
        const risky = /(?:from_port|to_port)\s*=\s*(22|3389|3306|5432|1433|27017|6379|9200)\b/.test(
          text,
        );
        out.push(
          f({
            rule: 'CFG-TF-001',
            kb: 'terraform-open-ingress',
            title: 'Security group allows traffic from anywhere (0.0.0.0/0)',
            severity: risky ? 'high' : 'medium',
            target: file,
            line: n,
            evidence: clip(l),
            confidence: 'medium',
          }),
        );
      }
      if (/\bacl\s*=\s*"public-read(?:-write)?"/.test(l))
        out.push(
          f({
            rule: 'CFG-TF-002',
            kb: 'terraform-public-bucket',
            title: 'Storage bucket is publicly readable',
            severity: 'high',
            target: file,
            line: n,
            evidence: clip(l),
            verified: true,
          }),
        );
      if (/\b(?:storage_encrypted|encrypted)\s*=\s*false/.test(l))
        out.push(
          f({
            rule: 'CFG-TF-003',
            kb: 'terraform-unencrypted',
            title: 'Storage encryption is disabled',
            severity: 'medium',
            target: file,
            line: n,
            evidence: clip(l),
            verified: true,
          }),
        );
      if (/\bpublicly_accessible\s*=\s*true/.test(l))
        out.push(
          f({
            rule: 'CFG-TF-004',
            kb: 'terraform-open-ingress',
            title: 'Database is publicly accessible',
            severity: 'high',
            target: file,
            line: n,
            evidence: clip(l),
            verified: true,
          }),
        );
      if (
        /\b(?:password|secret|access_key|secret_key)\s*=\s*"(?!\$\{|var\.)[^"\s]{6,}"/i.test(l) &&
        !/(change|example|your|xxx)/i.test(l)
      )
        out.push(
          f({
            rule: 'CFG-TF-005',
            kb: 'hardcoded-secret',
            title: 'Secret hard-coded in Terraform',
            severity: 'high',
            target: file,
            line: n,
            evidence: clip(l.replace(/"[^"\s]{6,}"/, '"<hidden>"')),
            confidence: 'medium',
            category: 'secrets',
          }),
        );
      if (/\bactions\s*=\s*\[\s*"\*"\s*\]|"Action"\s*:\s*"\*"/.test(l))
        out.push(
          f({
            rule: 'CFG-TF-006',
            kb: 'terraform-wildcard-iam',
            title: 'IAM policy allows all actions (*)',
            severity: 'high',
            target: file,
            line: n,
            evidence: clip(l),
            confidence: 'medium',
          }),
        );
    });
  }

  for (const file of paths.filter((p) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(p))) {
    const text = await read(index, file);
    if (text === null) continue;
    if (
      /pull_request_target/.test(text) &&
      /github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref/.test(text) &&
      /actions\/checkout/.test(text)
    ) {
      out.push(
        f({
          rule: 'CFG-GHA-010',
          kb: 'github-actions-injection',
          title: 'pull_request_target workflow checks out pull-request code',
          severity: 'high',
          target: file,
          line: text.split(/\r?\n/).findIndex((l) => /pull_request_target/.test(l)) + 1,
          evidence: 'Triggers on pull_request_target and references the PR head in a checkout',
          confidence: 'medium',
          category: 'ci-cd',
        }),
      );
    }
  }

  // .env files that exist in the tree (templates are skipped).
  for (const file of paths.filter(
    (p) => /(^|\/)\.env(\.[\w.]+)?$/.test(p) && !/\.(example|sample|template|dist)$/.test(p),
  )) {
    out.push(
      f({
        rule: 'CFG-ENV-001',
        kb: 'secret-file-committed',
        title: 'Environment file present in the project tree',
        severity: 'low',
        target: file,
        evidence:
          'Contents were not read. Confirm it is ignored by git and never shipped in a build or image.',
        verified: true,
        category: 'secrets',
      }),
    );
  }
  return out;
}
