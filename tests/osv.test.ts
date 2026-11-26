import { describe, expect, it, vi } from 'vitest';
import { lookupOsvCache, queryOsv, readOsvCache, writeOsvCache, type OsvCacheEntry } from '../src/intelligence/osv.js';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

describe('OSV intelligence client', () => {
  it('queries OSV with exact package versions and maps returned vulnerabilities', async () => {
    const fetcher = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      expect(init?.method).toBe('POST');
      const body = JSON.parse(String(init?.body)) as { queries: Array<{ version: string }> };
      expect(body.queries[0]?.version).toBe('1.2.3');
      return new Response(JSON.stringify({ results: [{ vulns: [{ id: 'GHSA-test', summary: 'Test issue' }] }] }), { status: 200 });
    }) as unknown as typeof fetch;
    const result = await queryOsv([{ ecosystem: 'npm', name: 'demo', version: '1.2.3' }], { fetcher });
    expect(result[0]?.vulnerabilities[0]?.id).toBe('GHSA-test');
  });

  it('deduplicates package tuples and rejects unbounded batches', async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({ results: [{ vulns: [] }] }))) as unknown as typeof fetch;
    const result = await queryOsv([
      { ecosystem: 'npm', name: 'demo', version: '1.0.0' },
      { ecosystem: 'npm', name: 'demo', version: '1.0.0' },
    ], { fetcher });
    expect(result).toHaveLength(1);
    await expect(queryOsv(Array.from({ length: 3 }, (_, i) => ({
      ecosystem: 'npm' as const, name: `p${i}`, version: '1.0.0',
    })), { fetcher, maxPackages: 2 })).rejects.toThrow(/limit/);
  });

  it('writes and reads a local cache with exact version lookup', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'kinga-osv-'));
    try {
      const file = path.join(dir, 'osv.json');
      const entry: OsvCacheEntry = {
        ecosystem: 'npm', name: 'demo', version: '1.0.0',
        vulnerabilities: [{ id: 'GHSA-cache' }], queriedAt: new Date().toISOString(),
      };
      await writeOsvCache(file, [entry]);
      const cache = await readOsvCache(file);
      expect(lookupOsvCache(cache, entry).map((v) => v.id)).toEqual(['GHSA-cache']);
      const stored = await readFile(file, 'utf8');
      expect(JSON.parse(stored).schemaVersion).toBe(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
