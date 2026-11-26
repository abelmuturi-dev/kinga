import type { RawFinding } from '../../core/types.js';
import type { RepoIndex } from '../../repo/index.js';
import { readTextFile } from '../../repo/read.js';
import { isRecord } from '../../util/json.js';
import type { AdvisoryDb, Ecosystem } from './advisories.js';
import { isExactVersion, parseVersion } from './version.js';

interface Dep {
  ecosystem: Ecosystem;
  name: string;
  /** Exact version when known (lockfile or pinned), otherwise the declared specifier. */
  version: string;
  exact: boolean;
  manifest: string;
  dev: boolean;
}

export interface DepScanOutput {
  findings: RawFinding[];
  manifests: string[];
  notes: string[];
}

async function read(index: RepoIndex, path: string, max = 3_000_000): Promise<string | null> {
  try {
    return (await readTextFile(index.inventory.root, path, { maxBytes: max })).text;
  } catch {
    return null;
  }
}

function dirOf(path: string): string {
  return path.includes('/') ? path.slice(0, path.lastIndexOf('/') + 1) : '';
}

function npmDeps(json: unknown, manifest: string): Dep[] {
  if (!isRecord(json)) return [];
  const out: Dep[] = [];
  for (const [section, dev] of [
    ['dependencies', false],
    ['devDependencies', true],
    ['optionalDependencies', false],
  ] as const) {
    const block = json[section];
    if (!isRecord(block)) continue;
    for (const [name, spec] of Object.entries(block)) {
      if (typeof spec !== 'string') continue;
      out.push({
        ecosystem: 'npm',
        name,
        version: spec,
        exact: isExactVersion(spec),
        manifest,
        dev,
      });
    }
  }
  return out;
}

function npmLock(json: unknown, manifest: string): Dep[] {
  if (!isRecord(json)) return [];
  const out: Dep[] = [];
  const packages = json['packages'];
  if (isRecord(packages)) {
    for (const [key, value] of Object.entries(packages)) {
      if (key === '' || !isRecord(value)) continue;
      const version = value['version'];
      if (typeof version !== 'string') continue;
      const name = key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
      out.push({
        ecosystem: 'npm',
        name,
        version,
        exact: true,
        manifest,
        dev: value['dev'] === true,
      });
    }
    return out;
  }
  const walk = (deps: unknown): void => {
    if (!isRecord(deps)) return;
    for (const [name, value] of Object.entries(deps)) {
      if (!isRecord(value)) continue;
      if (typeof value['version'] === 'string')
        out.push({
          ecosystem: 'npm',
          name,
          version: value['version'],
          exact: true,
          manifest,
          dev: value['dev'] === true,
        });
      walk(value['dependencies']);
    }
  };
  walk(json['dependencies']);
  return out;
}

function pyDeps(text: string, manifest: string): Dep[] {
  const out: Dep[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (line === '' || line.startsWith('-')) continue;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([\w.+-]+)/.exec(line);
    if (m?.[1] && m[2])
      out.push({ ecosystem: 'pypi', name: m[1], version: m[2], exact: true, manifest, dev: false });
  }
  return out;
}

function pomDeps(text: string, manifest: string): Dep[] {
  const out: Dep[] = [];
  for (const m of text.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const body = m[1] ?? '';
    const g = /<groupId>\s*([^<\s]+)\s*<\/groupId>/.exec(body)?.[1];
    const a = /<artifactId>\s*([^<\s]+)\s*<\/artifactId>/.exec(body)?.[1];
    const v = /<version>\s*([^<$\s]+)\s*<\/version>/.exec(body)?.[1];
    if (g && a && v)
      out.push({
        ecosystem: 'maven',
        name: `${g}:${a}`,
        version: v,
        exact: true,
        manifest,
        dev: false,
      });
  }
  return out;
}

function gradleDeps(text: string, manifest: string): Dep[] {
  const out: Dep[] = [];
  for (const m of text.matchAll(/['"]([\w.-]+):([\w.-]+):(\d[\w.-]*)['"]/g)) {
    if (m[1] && m[2] && m[3])
      out.push({
        ecosystem: 'maven',
        name: `${m[1]}:${m[2]}`,
        version: m[3],
        exact: true,
        manifest,
        dev: false,
      });
  }
  return out;
}

export async function scanDependencies(index: RepoIndex, db: AdvisoryDb): Promise<DepScanOutput> {
  const paths = index.inventory.files.map((p) => p.path);
  const manifests: string[] = [];
  const notes: string[] = [];
  const findings: RawFinding[] = [];
  const deps: Dep[] = [];

  const lockByDir = new Map<string, string>();
  for (const p of paths.filter((x) => /(^|\/)(package-lock\.json|npm-shrinkwrap\.json)$/.test(x)))
    lockByDir.set(dirOf(p), p);
  const otherLocks = paths.filter((x) => /(^|\/)(yarn\.lock|pnpm-lock\.yaml|bun\.lockb?)$/.test(x));

  for (const manifest of paths.filter((x) => /(^|\/)package\.json$/.test(x))) {
    const text = await read(index, manifest);
    if (text === null) continue;
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      continue;
    }
    manifests.push(manifest);
    const declared = npmDeps(json, manifest);
    const dir = dirOf(manifest);
    const lockPath = lockByDir.get(dir);
    const hasOtherLock = otherLocks.some((l) => dirOf(l) === dir);
    if (lockPath) {
      const lockText = await read(index, lockPath);
      let lockJson: unknown = null;
      try {
        lockJson = lockText ? JSON.parse(lockText) : null;
      } catch {
        notes.push(`${lockPath} could not be parsed as JSON.`);
      }
      deps.push(...npmLock(lockJson, lockPath));
    } else {
      deps.push(...declared);
      if (!hasOtherLock && declared.length > 0) {
        findings.push({
          rule: 'DEP-LCK-001',
          kb: 'no-lockfile',
          title: 'No lockfile for Node dependencies',
          severity: 'low',
          confidence: 'high',
          domain: 'deps',
          category: 'supply-chain',
          target: manifest,
          evidence: `${declared.length} dependencies declared with no package-lock.json, yarn.lock or pnpm-lock.yaml; installed versions are unknown and can change between builds.`,
          verified: true,
          verification: 'Observed in the file list.',
        });
      } else if (hasOtherLock) {
        notes.push(
          `${manifest}: versions are resolved from declarations only because the lockfile format (yarn/pnpm/bun) is not read.`,
        );
      }
    }
    const loose = declared.filter((d) => /^(\*|latest|x|)$/.test(d.version.trim()));
    if (loose.length > 0) {
      findings.push({
        rule: 'DEP-VER-001',
        kb: 'unpinned-dependency',
        title: 'Dependencies with unpinned versions ("*" or "latest")',
        severity: 'medium',
        confidence: 'high',
        domain: 'deps',
        category: 'supply-chain',
        target: manifest,
        evidence: loose
          .slice(0, 5)
          .map((d) => `${d.name}: "${d.version}"`)
          .join(', '),
        verified: true,
        verification: 'Observed in the file.',
      });
    }
    const git = declared.filter((d) => /^(git\+|github:|https?:\/\/)/.test(d.version));
    if (git.length > 0) {
      findings.push({
        rule: 'DEP-VER-002',
        kb: 'unpinned-dependency',
        title: 'Dependencies fetched from a Git or URL source',
        severity: 'low',
        confidence: 'high',
        domain: 'deps',
        category: 'supply-chain',
        target: manifest,
        evidence: git
          .slice(0, 4)
          .map((d) => `${d.name}: ${d.version}`)
          .join(', '),
        verified: true,
        verification: 'Observed in the file.',
      });
    }
    const scripts = isRecord(json) && isRecord(json['scripts']) ? json['scripts'] : {};
    for (const hook of ['preinstall', 'install', 'postinstall']) {
      const cmd = scripts[hook];
      if (
        typeof cmd === 'string' &&
        /\b(curl|wget)\b[^|]*\|\s*(ba)?sh|\beval\b|\bnc\b\s|base64\s+-d/.test(cmd)
      ) {
        findings.push({
          rule: 'DEP-SCR-001',
          kb: 'install-script',
          title: `Suspicious ${hook} script`,
          severity: 'high',
          confidence: 'medium',
          domain: 'deps',
          category: 'supply-chain',
          target: manifest,
          evidence: `${hook}: ${cmd.slice(0, 120)}`,
          verified: false,
          verification: 'Pattern match on the script text.',
        });
      }
    }
  }
  if (lockByDir.size > 0 && otherLocks.length > 0) {
    findings.push({
      rule: 'DEP-LCK-002',
      kb: 'no-lockfile',
      title: 'Multiple Node lockfiles',
      severity: 'low',
      confidence: 'high',
      domain: 'deps',
      category: 'supply-chain',
      target: [...lockByDir.values(), ...otherLocks].join(', '),
      evidence:
        'Different package managers can resolve different versions, so teammates and CI may not install the same tree.',
      verified: true,
      verification: 'Observed in the file list.',
    });
  }

  for (const req of paths.filter((x) => /(^|\/)requirements[\w.-]*\.txt$/.test(x))) {
    const text = await read(index, req);
    if (text === null) continue;
    manifests.push(req);
    deps.push(...pyDeps(text, req));
    const lines = text
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l !== '' && !l.startsWith('#') && !l.startsWith('-'));
    const unpinned = lines.filter((l) => /^[A-Za-z0-9._-]+(\[[^\]]+\])?\s*$/.test(l));
    if (lines.length >= 3 && unpinned.length > 0) {
      findings.push({
        rule: 'DEP-VER-003',
        kb: 'unpinned-dependency',
        title: 'Python requirements without pinned versions',
        severity: 'low',
        confidence: 'high',
        domain: 'deps',
        category: 'supply-chain',
        target: req,
        evidence: `${unpinned.length} of ${lines.length} entries have no version constraint (${unpinned.slice(0, 4).join(', ')})`,
        verified: true,
        verification: 'Observed in the file.',
      });
    }
  }
  for (const pom of paths.filter((x) => /(^|\/)pom\.xml$/.test(x))) {
    const text = await read(index, pom);
    if (text === null) continue;
    manifests.push(pom);
    deps.push(...pomDeps(text, pom));
  }
  for (const g of paths.filter((x) => /(^|\/)build\.gradle(\.kts)?$/.test(x))) {
    const text = await read(index, g);
    if (text === null) continue;
    manifests.push(g);
    deps.push(...gradleDeps(text, g));
  }

  // Advisory matching (de-duplicated by package@version).
  const seen = new Set<string>();
  for (const d of deps) {
    const version = d.exact ? d.version : (parseVersion(d.version) ?? []).join('.');
    if (version === '') continue;
    const key = `${d.ecosystem}:${d.name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    for (const hit of db.lookup(d.ecosystem, d.name, version)) {
      findings.push({
        rule: 'DEP-VUL-001',
        kb: 'vulnerable-dependency',
        title: `Vulnerable dependency: ${d.name} ${version}`,
        severity:
          d.dev && hit.advisory.severity !== 'critical'
            ? downgrade(hit.advisory.severity)
            : hit.advisory.severity,
        confidence: d.exact ? 'high' : 'medium',
        domain: 'deps',
        category: 'outdated-components',
        target: d.manifest,
        evidence: `${hit.advisory.id}: ${hit.advisory.summary}. Installed ${version}; fixed in ${hit.fixedIn}.${d.dev ? ' (development dependency)' : ''}${d.exact ? '' : ' Version taken from the declared range, not a lockfile.'}`,
        verified: d.exact,
        verification: d.exact
          ? 'Version read from a lockfile or exact pin and matched against the bundled advisory snapshot.'
          : 'Version inferred from a declared range; the installed version may be newer.',
        facts: {
          package: d.name,
          version,
          fixedIn: hit.fixedIn,
          advisory: hit.advisory.id,
          ecosystem: d.ecosystem,
        },
        tags: hit.advisory.cwe ?? [],
      });
    }
  }
  if (deps.length === 0 && manifests.length === 0)
    notes.push('No dependency manifests were found.');
  return { findings, manifests, notes };
}

function downgrade(s: RawFinding['severity']): RawFinding['severity'] {
  return s === 'high' ? 'medium' : s === 'medium' ? 'low' : s;
}
