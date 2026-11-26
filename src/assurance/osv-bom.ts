import {
  queryOsv,
  readOsvCache,
  writeOsvCache,
  type OsvEcosystem,
  type OsvPackage,
} from '../intelligence/osv.js';
import type { CycloneDxBom } from './sbom.js';

const ECOSYSTEMS: Record<string, OsvEcosystem> = {
  npm: 'npm',
  pypi: 'PyPI',
  maven: 'Maven',
  golang: 'Go',
  cargo: 'crates.io',
  gem: 'RubyGems',
  nuget: 'NuGet',
  composer: 'Packagist',
};

function packagesFromBom(bom: CycloneDxBom): OsvPackage[] {
  const result: OsvPackage[] = [];
  for (const component of bom.components) {
    const match = /^pkg:([^/]+)\/(.+)@([^?]+)(?:\?.*)?$/.exec(component.purl);
    if (!match?.[1] || !match[2] || !match[3]) continue;
    const ecosystem = ECOSYSTEMS[match[1]];
    if (!ecosystem) continue;
    try {
      result.push({
        ecosystem,
        name: decodeURIComponent(match[2]),
        version: decodeURIComponent(match[3]),
      });
    } catch {
      /* Ignore malformed package URLs. */
    }
  }
  return result;
}

/** Check exact SBOM package versions against OSV. Network use is explicit unless offline=true. */
export async function scanBomWithOsv(
  bom: CycloneDxBom,
  cacheFile: string,
  offline = false,
  refresh = false,
): Promise<{
  checked: number;
  vulnerabilities: Array<{ package: string; version: string; id: string; summary: string }>;
  cacheUpdated: boolean;
  notes: string[];
}> {
  if (offline && refresh) throw new Error('Choose either --offline or --refresh, not both.');
  const packages = packagesFromBom(bom);
  const cache = await readOsvCache(cacheFile);
  const key = (pkg: OsvPackage): string =>
    `${pkg.ecosystem.toLowerCase()}:${pkg.name.toLowerCase()}@${pkg.version}`;
  const entries = new Map((cache?.entries ?? []).map((entry) => [key(entry), entry]));
  const missing = refresh ? packages : packages.filter((pkg) => !entries.has(key(pkg)));
  const notes: string[] = [];
  let cacheUpdated = false;
  if (offline && missing.length)
    notes.push(`${missing.length} package version(s) are absent from the local OSV cache.`);
  if (!offline && missing.length) {
    const fresh = [];
    for (let offset = 0; offset < missing.length; offset += 100)
      fresh.push(...(await queryOsv(missing.slice(offset, offset + 100))));
    for (const entry of fresh) entries.set(key(entry), entry);
    await writeOsvCache(cacheFile, [...entries.values()]);
    cacheUpdated = true;
  }
  const vulnerabilities: Array<{ package: string; version: string; id: string; summary: string }> =
    [];
  for (const pkg of packages)
    for (const vuln of entries.get(key(pkg))?.vulnerabilities ?? []) {
      vulnerabilities.push({
        package: pkg.name,
        version: pkg.version,
        id: vuln.id,
        summary: vuln.summary ?? vuln.details?.slice(0, 180) ?? 'No summary supplied by OSV.',
      });
    }
  return { checked: packages.length, vulnerabilities, cacheUpdated, notes };
}
