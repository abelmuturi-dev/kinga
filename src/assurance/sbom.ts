import { randomUUID } from 'node:crypto';
import { readdir, readFile, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

export interface SbomComponent {
  type: 'library';
  name: string;
  version: string;
  purl: string;
}
export interface CycloneDxBom {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  serialNumber: string;
  version: 1;
  metadata: { timestamp: string; tools: Array<{ vendor: string; name: string; version: string }> };
  components: SbomComponent[];
}

const SKIP = new Set([
  '.git',
  'node_modules',
  'vendor',
  'dist',
  'build',
  '.venv',
  'venv',
  'coverage',
]);
const MAX_FILES = 20_000;
const MAX_BYTES = 4_000_000;

function add(out: Map<string, SbomComponent>, type: string, name: string, version: string): void {
  name = name.trim();
  version = version.trim();
  if (!name || !version || /^(?:\*|latest|x)$/i.test(version)) return;
  const key = `${type}:${name.toLowerCase()}@${version}`;
  if (out.has(key)) return;
  const purlType =
    (
      {
        pypi: 'pypi',
        golang: 'golang',
        cargo: 'cargo',
        gem: 'gem',
        nuget: 'nuget',
        composer: 'composer',
        maven: 'maven',
        npm: 'npm',
      } as Record<string, string>
    )[type] ?? 'generic';
  const encoded = encodeURIComponent(name).replace(/%2F/gi, '/');
  out.set(key, {
    type: 'library',
    name,
    version,
    purl: `pkg:${purlType}/${encoded}@${encodeURIComponent(version)}`,
  });
}

async function filesUnder(root: string): Promise<string[]> {
  const found: string[] = [];
  const queue = [{ dir: root, depth: 0 }];
  while (queue.length && found.length < MAX_FILES) {
    const current = queue.shift()!;
    let entries;
    try {
      entries = await readdir(current.dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const absolute = path.join(current.dir, entry.name);
      if (entry.isDirectory() && current.depth < 12 && !SKIP.has(entry.name)) {
        queue.push({ dir: absolute, depth: current.depth + 1 });
      } else if (entry.isFile()) {
        found.push(path.relative(root, absolute).split(path.sep).join('/'));
      }
      if (found.length >= MAX_FILES) break;
    }
  }
  return found;
}

async function readSmall(root: string, relative: string): Promise<string | null> {
  try {
    const data = await readFile(path.join(root, relative));
    return data.length <= MAX_BYTES ? data.toString('utf8') : null;
  } catch {
    return null;
  }
}

function parseNpm(text: string, out: Map<string, SbomComponent>): void {
  const json = JSON.parse(text) as { packages?: Record<string, { version?: string }> };
  for (const [key, value] of Object.entries(json.packages ?? {})) {
    const marker = 'node_modules/';
    const at = key.lastIndexOf(marker);
    if (at >= 0 && value.version) add(out, 'npm', key.slice(at + marker.length), value.version);
  }
}
function parsePython(text: string, out: Map<string, SbomComponent>): void {
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*==\s*([\w.+-]+)/.exec(
      line.replace(/\s+#.*$/, ''),
    );
    if (m?.[1] && m[2]) add(out, 'pypi', m[1], m[2]);
  }
}
function parseGo(text: string, out: Map<string, SbomComponent>): void {
  for (const m of text.matchAll(/^\s*(?:require\s+)?([^\s()]+)\s+(v\d[^\s]+)(?:\s+\/\/.*)?$/gm)) {
    if (m[1] && m[2] && !['module', 'go', 'toolchain'].includes(m[1]))
      add(out, 'golang', m[1], m[2]);
  }
}
function parseCargo(text: string, out: Map<string, SbomComponent>): void {
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const name = /^name\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    if (name && version) add(out, 'cargo', name, version);
  }
}
function parseGem(text: string, out: Map<string, SbomComponent>): void {
  const start = text.indexOf('  specs:');
  if (start < 0) return;
  for (const line of text.slice(start).split(/\r?\n/)) {
    const m = /^ {4}([A-Za-z0-9_.-]+) \(([^()]+)\)/.exec(line);
    if (m?.[1] && m[2]) add(out, 'gem', m[1], m[2]);
  }
}
function parseComposer(text: string, out: Map<string, SbomComponent>): void {
  const json = JSON.parse(text) as {
    packages?: Array<{ name?: string; version?: string }>;
    'packages-dev'?: Array<{ name?: string; version?: string }>;
  };
  for (const item of [...(json.packages ?? []), ...(json['packages-dev'] ?? [])]) {
    if (item.name && item.version) add(out, 'composer', item.name, item.version.replace(/^v/, ''));
  }
}
function parseMaven(text: string, out: Map<string, SbomComponent>): void {
  for (const block of text.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const body = block[1] ?? '';
    const group = /<groupId>\s*([^<\s]+)\s*<\/groupId>/.exec(body)?.[1];
    const artifact = /<artifactId>\s*([^<\s]+)\s*<\/artifactId>/.exec(body)?.[1];
    const version = /<version>\s*([^<$\s]+)\s*<\/version>/.exec(body)?.[1];
    if (group && artifact && version) add(out, 'maven', `${group}:${artifact}`, version);
  }
}
function parseNugetLock(text: string, out: Map<string, SbomComponent>): void {
  const json = JSON.parse(text) as {
    dependencies?: Record<string, Record<string, { resolved?: string }>>;
  };
  for (const framework of Object.values(json.dependencies ?? {})) {
    for (const [name, item] of Object.entries(framework))
      if (item.resolved) add(out, 'nuget', name, item.resolved);
  }
}
function parseNugetConfig(text: string, out: Map<string, SbomComponent>): void {
  for (const m of text.matchAll(
    /<package\b[^>]*\bid=["']([^"']+)["'][^>]*\bversion=["']([^"']+)["'][^>]*\/?\s*>/gi,
  )) {
    if (m[1] && m[2]) add(out, 'nuget', m[1], m[2]);
  }
}

/** Generate CycloneDX 1.5 from recognized manifests and lockfiles without executing project code. */
export async function buildCycloneDx(root: string): Promise<CycloneDxBom> {
  const absolute = path.resolve(root);
  const out = new Map<string, SbomComponent>();
  const parsers: Record<string, (text: string, out: Map<string, SbomComponent>) => void> = {
    'package-lock.json': parseNpm,
    'requirements.txt': parsePython,
    'go.mod': parseGo,
    'Cargo.lock': parseCargo,
    'Gemfile.lock': parseGem,
    'composer.lock': parseComposer,
    'pom.xml': parseMaven,
    'packages.lock.json': parseNugetLock,
    'packages.config': parseNugetConfig,
  };
  for (const file of await filesUnder(absolute)) {
    const parser = parsers[path.basename(file)];
    if (!parser) continue;
    const text = await readSmall(absolute, file);
    if (text === null) continue;
    try {
      parser(text, out);
    } catch {
      /* Skip malformed manifests; retain other results. */
    }
  }
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'Kinga', name: 'Kinga', version: '0.1.0' }],
    },
    components: [...out.values()].sort((a, b) => a.purl.localeCompare(b.purl)),
  };
}

export async function writeCycloneDx(bom: CycloneDxBom, output: string): Promise<void> {
  const file = path.resolve(output);
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(bom, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
}
