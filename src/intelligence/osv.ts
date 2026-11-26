import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';

export type OsvEcosystem =
  | 'npm'
  | 'PyPI'
  | 'Maven'
  | 'Go'
  | 'crates.io'
  | 'RubyGems'
  | 'NuGet'
  | 'Packagist'
  | 'Hex'
  | 'Pub';

export interface OsvPackage {
  ecosystem: OsvEcosystem;
  name: string;
  version: string;
}

export interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  references?: Array<{ type?: string; url?: string }>;
  severity?: Array<{ type?: string; score?: string }>;
  affected?: unknown[];
  [key: string]: unknown;
}

export interface OsvCacheEntry extends OsvPackage {
  vulnerabilities: OsvVulnerability[];
  queriedAt: string;
}

export interface OsvCache {
  schemaVersion: 1;
  source: 'https://api.osv.dev/v1/querybatch';
  updatedAt: string;
  entries: OsvCacheEntry[];
}

export interface OsvQueryOptions {
  fetcher?: typeof fetch;
  timeoutMs?: number;
  maxPackages?: number;
}

const OSV_ENDPOINT = 'https://api.osv.dev/v1/querybatch';
const DEFAULT_TIMEOUT_MS = 12_000;
const DEFAULT_MAX_PACKAGES = 100;

function packageKey(pkg: OsvPackage): string {
  return [pkg.ecosystem.toLowerCase(), pkg.name.trim().toLowerCase(), pkg.version.trim()].join(':');
}

function validatePackages(packages: readonly OsvPackage[], max: number): OsvPackage[] {
  if (packages.length === 0) return [];
  if (packages.length > max) throw new Error(`OSV batch exceeds the limit of ${max} packages.`);
  const seen = new Set<string>();
  const result: OsvPackage[] = [];
  for (const pkg of packages) {
    if (!pkg || typeof pkg.name !== 'string' || typeof pkg.version !== 'string' ||
        typeof pkg.ecosystem !== 'string' || pkg.name.trim() === '' || pkg.version.trim() === '') {
      throw new Error('Every OSV package needs a non-empty ecosystem, name and exact version.');
    }
    const normalized = { ecosystem: pkg.ecosystem, name: pkg.name.trim(), version: pkg.version.trim() };
    const key = packageKey(normalized);
    if (!seen.has(key)) {
      seen.add(key);
      result.push(normalized);
    }
  }
  return result;
}

function isVulnerability(value: unknown): value is OsvVulnerability {
  return typeof value === 'object' && value !== null &&
    typeof (value as { id?: unknown }).id === 'string';
}

/** Query OSV in a bounded batch. This function never executes package-manager commands. */
export async function queryOsv(
  packages: readonly OsvPackage[],
  options: OsvQueryOptions = {},
): Promise<OsvCacheEntry[]> {
  const batch = validatePackages(packages, options.maxPackages ?? DEFAULT_MAX_PACKAGES);
  if (batch.length === 0) return [];
  const fetcher = options.fetcher ?? fetch;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  try {
    const response = await fetcher(OSV_ENDPOINT, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({
        queries: batch.map((pkg) => ({
          package: { name: pkg.name, ecosystem: pkg.ecosystem },
          version: pkg.version,
        })),
      }),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`OSV request failed with HTTP ${response.status}.`);
    const payload: unknown = await response.json();
    if (typeof payload !== 'object' || payload === null ||
        !Array.isArray((payload as { results?: unknown }).results)) {
      throw new Error('OSV returned an invalid batch response.');
    }
    const results = (payload as { results: unknown[] }).results;
    if (results.length !== batch.length) throw new Error('OSV returned an unexpected result count.');
    const queriedAt = new Date().toISOString();
    return batch.map((pkg, index) => {
      const result = results[index];
      const vulnerabilities = typeof result === 'object' && result !== null &&
        Array.isArray((result as { vulns?: unknown }).vulns)
        ? (result as { vulns: unknown[] }).vulns.filter(isVulnerability)
        : [];
      return { ...pkg, vulnerabilities, queriedAt };
    });
  } finally {
    clearTimeout(timeout);
  }
}

/** Load a previously downloaded OSV cache. Invalid or unsupported caches fail closed. */
export async function readOsvCache(file: string): Promise<OsvCache | null> {
  let raw: string;
  try {
    raw = await readFile(file, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
  const value: unknown = JSON.parse(raw);
  if (typeof value !== 'object' || value === null) throw new Error('Invalid OSV cache.');
  const cache = value as Partial<OsvCache>;
  if (cache.schemaVersion !== 1 || cache.source !== OSV_ENDPOINT || !Array.isArray(cache.entries)) {
    throw new Error('Unsupported or invalid OSV cache schema.');
  }
  return cache as OsvCache;
}

/** Atomically persist OSV results locally with restrictive file permissions. */
export async function writeOsvCache(file: string, entries: readonly OsvCacheEntry[]): Promise<OsvCache> {
  const absolute = path.resolve(file);
  const directory = path.dirname(absolute);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const cache: OsvCache = {
    schemaVersion: 1,
    source: OSV_ENDPOINT,
    updatedAt: new Date().toISOString(),
    entries: [...entries],
  };
  const temporary = `${absolute}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(cache, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  await rename(temporary, absolute);
  return cache;
}

/** Return cached results for an exact ecosystem/name/version tuple. */
export function lookupOsvCache(cache: OsvCache | null, pkg: OsvPackage): OsvVulnerability[] {
  if (!cache) return [];
  const key = packageKey(pkg);
  return cache.entries.find((entry) => packageKey(entry) === key)?.vulnerabilities ?? [];
}
