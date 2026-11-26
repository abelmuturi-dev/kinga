import { BRAND } from '../../brand.js';
import type { RawFinding, TargetSummary } from '../../core/types.js';
import type { Runner } from '../../platform/exec.js';
import { safeGitArgs, safeGitEnv } from '../../project/git.js';
import { RepoIndex } from '../../repo/index.js';
import { languageOf } from '../../repo/languages.js';
import { readTextFile } from '../../repo/read.js';
import { isTestFile } from '../../repo/tests-map.js';
import { findSecretTokens } from '../../security/redact.js';
import { mapLimit } from '../../util/concurrency.js';
import { scanDependencies } from '../deps/scan.js';
import type { AdvisoryDb } from '../deps/advisories.js';
import { configFindings } from './config.js';
import { CODE_RULES, type CodeRule } from './rules.js';

export interface CodeScanOptions {
  maxFileBytes: number;
  advisories: AdvisoryDb;
  extraRules?: readonly CodeRule[];
}

export const DEFAULT_CODE_OPTIONS = { maxFileBytes: 400_000 };

export interface CodeScanOutput {
  findings: RawFinding[];
  summary: Extract<TargetSummary, { kind: 'project' }>;
  index: RepoIndex;
}

export function isDocOrExample(path: string): boolean {
  const kind = languageOf(path)?.kind;
  return (
    kind === 'docs' ||
    /(^|\/)(docs?|examples?|samples?|fixtures?|demo|__mocks__)\//i.test(path) ||
    /\.(md|rst|txt)$/i.test(path)
  );
}

const CONFIG_NAME =
  /^(Dockerfile[\w.-]*|docker-compose[\w.-]*\.ya?ml|compose\.ya?ml|\.env\.[\w.]+|[\w.-]+\.(sh|ya?ml|json|toml|ini|cfg|conf|properties|xml|tf|tfvars))$/i;

function scannable(path: string): boolean {
  const base = path.slice(path.lastIndexOf('/') + 1);
  const info = languageOf(path);
  return (
    info?.kind === 'code' ||
    info?.name === 'Template' ||
    info?.name === 'HTML' ||
    CONFIG_NAME.test(base) ||
    /^\.github\/workflows\//.test(path)
  );
}

function clip(line: string): string {
  const t = line.trim();
  return t.length > 160 ? `${t.slice(0, 160)}…` : t;
}

function mask(line: string, match: RegExpExecArray): string {
  const value = match[2] ?? match[1] ?? match[0];
  const shown = line.trim().replace(value, `<${value.length} chars hidden>`);
  return shown.length > 160 ? `${shown.slice(0, 160)}…` : shown;
}

export async function runCodeScan(
  root: string,
  run: Runner,
  env: NodeJS.ProcessEnv,
  options: CodeScanOptions,
): Promise<CodeScanOutput> {
  const index = new RepoIndex(root, run, env);
  await index.refresh();
  const { inventory } = index;
  const findings: RawFinding[] = [];
  const rules = [...CODE_RULES, ...(options.extraRules ?? [])];
  const targets = inventory.files.filter(
    (f) => scannable(f.path) && f.size <= options.maxFileBytes,
  );
  let skipped = inventory.files.length - targets.length;
  let suppressed = 0;
  const ignoreRe = new RegExp(BRAND.ignoreMarker);
  const ignoreNext = new RegExp(`${BRAND.ignoreMarker}-next-line`);

  // Pattern rules, line by line.
  await mapLimit(targets, 16, async (file) => {
    let text: string;
    try {
      text = (await readTextFile(inventory.root, file.path, { maxBytes: options.maxFileBytes }))
        .text;
    } catch {
      skipped++;
      return;
    }
    const lines = text.split(/\r?\n/);
    const test = isTestFile(file.path);
    const doc = isDocOrExample(file.path);
    const applicable = rules.filter(
      (r) => r.appliesTo(file.path) && (r.includeTests === true || !(test || doc)),
    );
    if (applicable.length === 0) return;
    const hits = new Set<string>();
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      if (line.length > 2000 || line.trim() === '') continue;
      if (ignoreNext.test(line)) continue; // the marker comment itself is not a suppressed finding
      if (ignoreRe.test(line) || ignoreNext.test(lines[i - 1] ?? '')) {
        suppressed++;
        continue;
      }
      for (const rule of applicable) {
        const m = new RegExp(rule.pattern.source, rule.pattern.flags.replace('g', '')).exec(line);
        if (!m) continue;
        if (rule.accept && !rule.accept(line, m)) continue;
        const key = `${rule.id}:${i}`;
        if (hits.has(key)) continue;
        hits.add(key);
        findings.push({
          rule: rule.id,
          kb: rule.kb,
          title: rule.title,
          severity: rule.severity,
          confidence: rule.confidence,
          domain: rule.domain,
          category: rule.category,
          target: file.path,
          line: i + 1,
          evidence: rule.maskValue ? mask(line, m) : clip(line),
          verified: false,
          verification:
            'Pattern match on the source line. The surrounding code was not executed or data-flow analysed, so confirm that attacker-controlled data really reaches this line.',
        });
      }
    }
  });

  // Token-shaped secrets in any readable file (including config and templates).
  const secretTargets = inventory.files.filter(
    (f) => f.size <= options.maxFileBytes && languageOf(f.path)?.kind !== 'docs',
  );
  await mapLimit(secretTargets, 16, async (file) => {
    let text: string;
    try {
      text = (await readTextFile(inventory.root, file.path, { maxBytes: options.maxFileBytes }))
        .text;
    } catch {
      return;
    }
    const found = findSecretTokens(text);
    if (found.length === 0) return;
    const first = found[0]!;
    const lineNo = text.slice(0, first.index).split('\n').length;
    const lowValue = isTestFile(file.path) || isDocOrExample(file.path);
    const key = first.kind === 'private-key';
    findings.push({
      rule: 'CODE-SEC-003',
      kb: 'hardcoded-secret',
      title: key ? 'Private key material in a source file' : 'Token-shaped secret in a source file',
      severity: lowValue ? 'low' : key ? 'critical' : 'high',
      confidence: lowValue ? 'low' : key ? 'high' : 'medium',
      domain: 'secrets',
      category: 'secrets',
      target: file.path,
      line: lineNo,
      evidence: `${first.preview}${found.length > 1 ? ` (+${found.length - 1} more in this file)` : ''}; value not shown`,
      verified: false,
      verification:
        'The text matches a known credential format. Kinga never tests whether a secret is live.',
    });
  });

  // Project-level: secret files, Docker, Kubernetes, Terraform, CI.
  findings.push(...(await secretFileFindings(index, run, env)));
  findings.push(...(await configFindings(index)));

  // Dependencies.
  const deps = await scanDependencies(index, options.advisories);
  findings.push(...deps.findings);

  return {
    findings,
    index,
    summary: {
      kind: 'project',
      path: inventory.root,
      filesScanned: Math.max(
        0,
        targets.length - Math.max(0, skipped - (inventory.files.length - targets.length)),
      ),
      filesSkipped: skipped,
      manifests: deps.manifests,
      truncated: inventory.truncated,
      suppressed,
      notes: deps.notes,
    },
  };
}

async function secretFileFindings(
  index: RepoIndex,
  run: Runner,
  env: NodeJS.ProcessEnv,
): Promise<RawFinding[]> {
  const out: RawFinding[] = [];
  const { inventory } = index;
  for (const secret of inventory.secretFiles) {
    const tracked = inventory.tracked?.has(secret) ?? false;
    let ignored: boolean | null = null;
    if (!tracked && inventory.usedGit) {
      const r = await run('git', safeGitArgs(['check-ignore', '-q', '--', secret]), {
        cwd: inventory.root,
        env: safeGitEnv(env),
        timeoutMs: 10_000,
      });
      ignored = r.exitCode === 0 ? true : r.exitCode === 1 ? false : null;
    }
    if (tracked) {
      out.push({
        rule: 'CODE-SEC-010',
        kb: 'secret-file-committed',
        title: 'Secret-bearing file is committed to git',
        severity: 'high',
        confidence: 'high',
        domain: 'secrets',
        category: 'secrets',
        target: secret,
        evidence: `git tracks "${secret}" (contents were not read)`,
        verified: true,
        verification: 'Observed in the git index.',
      });
    } else if (ignored === false) {
      out.push({
        rule: 'CODE-SEC-011',
        kb: 'secret-file-committed',
        title: 'Secret-bearing file is not covered by .gitignore',
        severity: 'medium',
        confidence: 'high',
        domain: 'secrets',
        category: 'secrets',
        target: secret,
        evidence: `"${secret}" exists, is untracked and is not ignored, so \`git add .\` would commit it`,
        verified: true,
        verification: 'Observed with git check-ignore.',
      });
    }
  }
  return out;
}
