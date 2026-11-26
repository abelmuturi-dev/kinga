import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { EMPTY_CONFIG } from '../src/core/config.js';
import { scan } from '../src/framework.js';
import { runCommand } from '../src/platform/exec.js';

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), 'kinga-'));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function put(rel: string, text: string): Promise<void> {
  await mkdir(path.dirname(path.join(dir, rel)), { recursive: true });
  await writeFile(path.join(dir, rel), text);
}

const run = (config = EMPTY_CONFIG) =>
  scan({
    webTargets: [],
    projectPaths: [dir],
    web: {},
    config,
    version: 't',
    run: runCommand,
    env: { PATH: process.env['PATH'] ?? '' },
    sleep: async () => undefined,
  });

describe('code scan', () => {
  it('detects injection, secrets and weak crypto with line numbers', async () => {
    await put(
      'src/a.js',
      "db.query(`SELECT * FROM u WHERE id = ${req.query.id}`);\nconst h = crypto.createHash('md5');\n",
    );
    const r = await run();
    const rules = r.findings.map((f) => `${f.rule}@${f.line}`);
    expect(rules).toContain('CODE-INJ-002@1');
    expect(rules).toContain('CODE-CRY-001@2');
  });

  it('does not flag Node exec() as Python-style dynamic execution', async () => {
    await put('src/a.js', "exec('ls');\nrun(`x`);\n");
    const r = await run();
    expect(r.findings.some((f) => f.rule === 'CODE-INJ-007' || f.rule === 'CODE-INJ-004')).toBe(
      false,
    );
  });

  it('flags Python exec() but skips test files', async () => {
    await put('a.py', 'exec(code_from_user)\n');
    await put('tests/test_a.py', 'exec(code_from_user)\n');
    const r = await run();
    const hits = r.findings.filter((f) => f.rule === 'CODE-INJ-007');
    expect(hits.map((h) => h.target)).toEqual(['a.py']);
  });

  it('never prints secret values in evidence', async () => {
    await put(
      'src/k.js',
      'const dbpass = "Sup3rS3cretPassw0rd";\nconst k = "sk_live_abcdef1234567890ABCDEF";\n',
    );
    const r = await run();
    const text = JSON.stringify(r);
    expect(text).not.toContain('Sup3rS3cretPassw0rd');
    expect(text).not.toContain('abcdef1234567890ABCDEF');
    expect(r.findings.some((f) => f.kb === 'hardcoded-secret')).toBe(true);
  });

  it('ignores placeholders and honours the ignore comment', async () => {
    await put(
      'src/a.js',
      'const password = "changeme-example";\n// kinga-ignore-next-line\nconst x = crypto.createHash("md5");\n',
    );
    const r = await run();
    expect(r.findings).toHaveLength(0);
    expect(r.targets[0]?.kind === 'project' && r.targets[0].suppressed).toBe(1);
  });

  it('finds vulnerable dependencies from a lockfile and reports the fixed version', async () => {
    await put('package.json', JSON.stringify({ dependencies: { minimist: '^1.2.0' } }));
    await put(
      'package-lock.json',
      JSON.stringify({
        lockfileVersion: 3,
        packages: { '': {}, 'node_modules/minimist': { version: '1.2.5' } },
      }),
    );
    const r = await run();
    const f = r.findings.find((x) => x.rule === 'DEP-VUL-001');
    expect(f?.advice.summary).toContain('1.2.6');
    expect(f?.verified).toBe(true);
  });

  it('flags Docker, compose, Terraform and workflow problems', async () => {
    await put('Dockerfile', 'FROM node:latest\nCMD ["node","x"]\n');
    await put('docker-compose.yml', 'services:\n  a:\n    privileged: true\n');
    await put('main.tf', 'resource "x" "y" { acl = "public-read" }\n');
    await put(
      '.github/workflows/ci.yml',
      'on: push\njobs:\n  a:\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n',
    );
    const r = await run();
    const rules = new Set(r.findings.map((f) => f.rule));
    for (const id of ['CFG-DKR-001', 'CFG-DKR-002', 'CFG-DKR-006', 'CFG-TF-002', 'CODE-GHA-001'])
      expect(rules.has(id), id).toBe(true);
  });

  it('applies ignoreRules, ignorePaths and custom rules from config', async () => {
    await put('src/a.js', 'const h = crypto.createHash("md5");\nconsole.log("TODO-INTERNAL");\n');
    await put('gen/b.js', 'const h = crypto.createHash("md5");\n');
    const r = await run({
      ...EMPTY_CONFIG,
      ignorePaths: ['gen/'],
      customRules: [
        {
          id: 'CUSTOM-001',
          kb: 'custom',
          title: 'Internal marker',
          severity: 'low',
          confidence: 'medium',
          domain: 'code',
          category: 'custom',
          pattern: /TODO-INTERNAL/,
          appliesTo: () => true,
        },
      ],
    });
    expect(r.findings.filter((f) => f.rule === 'CODE-CRY-001').map((f) => f.target)).toEqual([
      'src/a.js',
    ]);
    expect(r.findings.some((f) => f.rule === 'CUSTOM-001')).toBe(true);
    const r2 = await run({ ...EMPTY_CONFIG, ignoreRules: ['CODE-CRY-001'] });
    expect(r2.findings.some((f) => f.rule === 'CODE-CRY-001')).toBe(false);
  });

  it('produces correlated insights', async () => {
    await put(
      'src/a.js',
      'db.query(`SELECT * FROM u WHERE id = ${req.query.id}`);\napp.use((e, req, res) => res.json(e.stack));\n',
    );
    const r = await run();
    expect(r.insights.some((i) => i.id === 'INS-005')).toBe(true);
  });

  it('fails clearly for a missing directory', async () => {
    await expect(
      scan({
        webTargets: [],
        projectPaths: [path.join(dir, 'nope')],
        web: {},
        config: EMPTY_CONFIG,
        version: 't',
        run: runCommand,
        env: {},
        sleep: async () => undefined,
      }),
    ).rejects.toThrow(/not a directory/);
  });
});
