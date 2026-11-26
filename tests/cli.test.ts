import { mkdtemp, writeFile, rm, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../src/cli.js';
import { fakeContext } from './helpers/ctx.js';

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), 'kinga-cli-'));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('cli', () => {
  it('prints version and help', async () => {
    const { ctx, out } = fakeContext(dir);
    expect(await run(['--version'], ctx)).toBe(0);
    expect(out[0]).toBe('9.9.9');
    const h = fakeContext(dir);
    expect(await run([], h.ctx)).toBe(0);
    expect(h.out.join('\n')).toContain('kinga scan');
  });

  it('suggests a command for a typo and exits 2', async () => {
    const { ctx, err } = fakeContext(dir);
    expect(await run(['scna'], ctx)).toBe(2);
    expect(err.join('\n')).toContain('Did you mean "scan"');
  });

  it('--fail-on gives a non-zero exit code when findings meet the threshold', async () => {
    await writeFile(path.join(dir, 'a.py'), 'import pickle\npickle.loads(x)\n');
    const a = fakeContext(dir);
    expect(await run(['code', dir, '--fail-on', 'high'], a.ctx)).toBe(1);
    const b = fakeContext(dir);
    expect(await run(['code', dir, '--fail-on', 'critical'], b.ctx)).toBe(0);
  });

  it('writes html, sarif and markdown reports outside the project, and refuses inside', async () => {
    await writeFile(path.join(dir, 'a.py'), 'import pickle\npickle.loads(x)\n');
    const outDir = await mkdtemp(path.join(os.tmpdir(), 'kinga-out-'));
    try {
      for (const fmt of ['html', 'sarif', 'markdown', 'json']) {
        const { ctx } = fakeContext(dir);
        expect(await run(['code', dir, '-f', fmt, '-o', path.join(outDir, `r.${fmt}`)], ctx)).toBe(
          0,
        );
      }
      const sarif = JSON.parse(await readFile(path.join(outDir, 'r.sarif'), 'utf8'));
      expect(sarif.version).toBe('2.1.0');
      expect(sarif.runs[0].results.length).toBeGreaterThan(0);
      expect(await readFile(path.join(outDir, 'r.html'), 'utf8')).toContain('<!doctype html>');
      const { ctx, err } = fakeContext(dir);
      expect(await run(['code', dir, '-o', path.join(dir, 'report.txt')], ctx)).toBe(1);
      expect(err.join('\n')).toContain('inside the scanned project');
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  });

  it('baseline hides known findings on the next scan', async () => {
    await writeFile(path.join(dir, 'a.py'), 'import pickle\npickle.loads(x)\n');
    await writeFile(
      path.join(dir, 'kinga.config.json'),
      JSON.stringify({ baseline: '.kinga/baseline.json' }),
    );
    const b = fakeContext(dir);
    expect(await run(['baseline', dir], b.ctx)).toBe(0);
    const { ctx, out } = fakeContext(dir);
    expect(await run(['code', dir, '-f', 'json'], ctx)).toBe(0);
    const json = JSON.parse(out.join('\n'));
    expect(json.findings).toHaveLength(0);
    expect(json.baselined).toBeGreaterThan(0);
  });

  it('ask and topics work offline', async () => {
    const a = fakeContext(dir);
    expect(await run(['ask', 'how', 'to', 'fix', 'xss', 'in', 'react'], a.ctx)).toBe(0);
    expect(a.out.join('\n')).toContain('Answered offline');
    const t = fakeContext(dir);
    expect(await run(['topics'], t.ctx)).toBe(0);
    expect(t.out.length).toBeGreaterThan(50);
  });
});
