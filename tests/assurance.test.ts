import { describe, expect, it, vi } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  buildCycloneDx,
  compareScanResults,
  inspectJavaScriptAsset,
  mapFindingToCompliance,
  rephraseWithLocalModel,
  scanBomWithOsv,
} from '../src/assurance/index.js';
import { writeOsvCache } from '../src/intelligence/osv.js';
import type { Finding, ScanResult } from '../src/core/types.js';

const finding = (over: Partial<Finding> = {}): Finding => ({
  id: 'x',
  rule: 'CODE-INJ-001',
  kb: 'command-injection',
  title: 'Command injection',
  severity: 'high',
  confidence: 'medium',
  domain: 'code',
  category: 'injection',
  target: 'src/app.ts',
  line: 1,
  evidence: 'exec(userInput)',
  verified: false,
  verification: 'Pattern match',
  cwe: ['CWE-78'],
  owasp: ['A03:2021 Injection'],
  risk: 65,
  fingerprint: 'fingerprint-x',
  advice: {
    summary: 'Fix it',
    why: 'Why',
    steps: ['Step'],
    examples: [],
    verify: 'Check',
    references: [],
    effort: 'hours',
  },
  ...over,
});
const scan = (findings: Finding[]): ScanResult => ({
  tool: { name: 'Kinga', version: '0.1.0' },
  startedAt: new Date().toISOString(),
  durationMs: 1,
  targets: [],
  findings,
  insights: [],
  fixPlan: [],
  fixBundles: [],
  stack: { detected: [] },
  baselined: 0,
  notAssessed: [],
});

describe('assurance module', () => {
  it('builds CycloneDX from npm, Python, Go, Rust and NuGet lockfiles', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'kinga-sbom-'));
    try {
      await mkdir(path.join(root, 'nested'), { recursive: true });
      await writeFile(
        path.join(root, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': {},
            'node_modules/express': { version: '4.18.2' },
            'node_modules/@scope/pkg': { version: '1.2.3' },
          },
        }),
      );
      await writeFile(path.join(root, 'requirements.txt'), 'Django==4.2.1\nrequests>=2.0\n');
      await writeFile(
        path.join(root, 'nested', 'go.mod'),
        'module example.test/app\nrequire github.com/example/lib v1.2.3\n',
      );
      await writeFile(
        path.join(root, 'nested', 'Cargo.lock'),
        '[[package]]\nname = "serde"\nversion = "1.0.1"\n',
      );
      await writeFile(
        path.join(root, 'packages.lock.json'),
        JSON.stringify({
          dependencies: { 'net8.0': { 'Newtonsoft.Json': { resolved: '13.0.1' } } },
        }),
      );
      const bom = await buildCycloneDx(root);
      expect(bom.bomFormat).toBe('CycloneDX');
      expect(bom.specVersion).toBe('1.5');
      expect(bom.components.map((c) => c.name)).toEqual(
        expect.arrayContaining([
          'express',
          '@scope/pkg',
          'Django',
          'github.com/example/lib',
          'serde',
          'Newtonsoft.Json',
        ]),
      );
      expect(bom.components.some((c) => c.name === 'requests')).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('maps findings to indicative compliance controls', () => {
    const controls = mapFindingToCompliance(finding());
    expect(controls.some((c) => c.framework === 'PCI-DSS-4.0' && c.control === '6.2')).toBe(true);
    expect(controls.every((c) => c.confidence === 'indicative')).toBe(true);
  });

  it('compares scans using finding fingerprints', () => {
    const delta = compareScanResults(
      scan([finding(), finding({ fingerprint: 'old' })]),
      scan([finding(), finding({ fingerprint: 'new' })]),
    );
    expect(delta.persisting).toHaveLength(1);
    expect(delta.added.map((f) => f.fingerprint)).toEqual(['new']);
    expect(delta.resolved.map((f) => f.fingerprint)).toEqual(['old']);
  });

  it('returns redacted JavaScript indicators only', () => {
    const results = inspectJavaScriptAsset(
      'const api_key = "sk_test_12345678901234567890";\n//# sourceMappingURL=app.js.map',
    );
    expect(results.map((r) => r.kind)).toEqual(['possible-api-key', 'source-map-reference']);
    expect(JSON.stringify(results)).not.toContain('sk_test_');
  });

  it('checks an SBOM against cached OSV findings without network in offline mode', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'kinga-osv-bom-'));
    try {
      const cache = path.join(root, 'cache.json');
      await writeOsvCache(cache, [
        {
          ecosystem: 'npm',
          name: 'express',
          version: '4.18.2',
          queriedAt: new Date().toISOString(),
          vulnerabilities: [{ id: 'GHSA-test', summary: 'Example issue' }],
        },
      ]);
      const bom = {
        bomFormat: 'CycloneDX' as const,
        specVersion: '1.5' as const,
        serialNumber: 'urn:uuid:test',
        version: 1 as const,
        metadata: { timestamp: new Date().toISOString(), tools: [] },
        components: [
          {
            type: 'library' as const,
            name: 'express',
            version: '4.18.2',
            purl: 'pkg:npm/express@4.18.2',
          },
        ],
      };
      const result = await scanBomWithOsv(bom, cache, true);
      expect(result.vulnerabilities[0]?.id).toBe('GHSA-test');
      expect(result.cacheUpdated).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('calls only the fixed loopback Ollama endpoint for local advice rephrasing', async () => {
    const fetcher = vi.fn(async (url: string | URL | Request) => {
      expect(String(url)).toBe('http://127.0.0.1:11434/api/generate');
      return new Response(JSON.stringify({ response: 'Simplified wording.' }), { status: 200 });
    }) as unknown as typeof fetch;
    const result = await rephraseWithLocalModel(
      { summary: 'Fix', why: 'Why', steps: ['Do'], verify: 'Test' },
      'qwen2.5:3b',
      { fetcher },
    );
    expect(result).toBe('Simplified wording.');
    await expect(
      rephraseWithLocalModel({ summary: '', why: '', steps: [], verify: '' }, '../remote', {
        fetcher,
      }),
    ).rejects.toThrow(/model name/);
  });
});
