import { describe, expect, it } from 'vitest';
import { EMPTY_CONFIG } from '../src/core/config.js';
import { scan } from '../src/framework.js';
import { runCommand } from '../src/platform/exec.js';
import { normalizeTarget } from '../src/scanners/web/scan.js';
import { parseCsp } from '../src/scanners/web/checks/headers.js';
import { parseSetCookie } from '../src/scanners/web/checks/cookies.js';
import { HttpClient, isAllowedRedirect } from '../src/scanners/web/http.js';
import { withServer, type Handler } from './helpers/server.js';

const base = {
  projectPaths: [] as string[],
  config: EMPTY_CONFIG,
  version: 't',
  run: runCommand,
  env: {},
  sleep: async () => undefined,
};

const insecure: Handler = (req, res) => {
  const url = (req.url ?? '/').split('?')[0];
  if (url === '/.env') {
    res.writeHead(200, { 'content-type': 'application/octet-stream' });
    return res.end('DB_HOST=x\nDB_PASSWORD=hunter2hunter2\n');
  }
  if (url === '/.git/HEAD') return void res.writeHead(200).end('ref: refs/heads/main\n');
  if (url === '/') {
    res.writeHead(200, {
      'content-type': 'text/html',
      'set-cookie': 'sid=1; Path=/',
      server: 'nginx/1.2',
      'access-control-allow-origin': String(req.headers.origin ?? '*'),
      'access-control-allow-credentials': 'true',
    });
    return res.end(
      '<html><body><form method="post" action="/x"><input type="password" name="p"></form></body></html>',
    );
  }
  res.writeHead(404).end('nope');
};

describe('web scan', () => {
  it('passive scan reports headers and cookies but sends no probes', async () => {
    const seen: string[] = [];
    await withServer(
      (req, res) => {
        seen.push(req.url ?? '');
        insecure(req, res);
      },
      async (url) => {
        const r = await scan({ ...base, webTargets: [url], web: { delayMs: 0 } });
        const rules = r.findings.map((f) => f.rule);
        expect(rules).toContain('WEB-CSP-001');
        expect(rules).toContain('WEB-CKE-002');
        expect(rules).not.toContain('WEB-EXP-002');
        expect(seen).not.toContain('/.env');
        expect(
          seen.every((p) => ['/', '/robots.txt', '/.well-known/security.txt'].includes(p)),
        ).toBe(true);
      },
    );
  });

  it('active scan finds exposed files without ever recording their contents', async () => {
    await withServer(insecure, async (url) => {
      const r = await scan({ ...base, webTargets: [url], web: { level: 'active', delayMs: 0 } });
      const rules = r.findings.map((f) => f.rule);
      expect(rules).toContain('WEB-EXP-002');
      expect(rules).toContain('WEB-EXP-001');
      expect(rules).toContain('WEB-COR-001');
      expect(JSON.stringify(r)).not.toContain('hunter2hunter2');
      expect(r.insights.some((i) => i.id === 'INS-001')).toBe(true);
      expect(r.stack.detected.some((d) => d.stack === 'nginx')).toBe(true);
      expect(
        r.fixBundles.some((b) => b.stack === 'nginx' && b.code.includes('Content-Security-Policy')),
      ).toBe(true);
    });
  });

  it('does not report exposure when a catch-all page answers every path', async () => {
    await withServer(
      (_q, res) => {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end('<html>app shell</html>');
      },
      async (url) => {
        const r = await scan({ ...base, webTargets: [url], web: { level: 'active', delayMs: 0 } });
        expect(r.findings.some((f) => f.rule.startsWith('WEB-EXP'))).toBe(false);
      },
    );
  });

  it('refuses active scans of non-local hosts without authorisation', async () => {
    await expect(
      scan({ ...base, webTargets: ['https://example.com'], web: { level: 'active' } }),
    ).rejects.toThrow(/--authorized/);
  });

  it('enforces the request budget', async () => {
    await withServer(insecure, async (url) => {
      const r = await scan({
        ...base,
        webTargets: [url],
        web: { level: 'active', delayMs: 0, maxRequests: 4 },
      });
      const t = r.targets[0];
      expect(t?.kind === 'web' && t.requests).toBeLessThanOrEqual(4);
    });
  });

  it('reports an unreachable target instead of crashing', async () => {
    const r = await scan({
      ...base,
      webTargets: ['http://127.0.0.1:1'],
      web: { delayMs: 0, timeoutMs: 1000 },
    });
    expect(r.findings[0]?.rule).toBe('WEB-NET-000');
  });
});

describe('web helpers', () => {
  it('normalises targets', () => {
    expect(normalizeTarget('example.com').toString()).toBe('https://example.com/');
    expect(normalizeTarget('localhost:3000').protocol).toBe('http:');
    expect(() => normalizeTarget('ftp://x')).toThrow();
    expect(() => normalizeTarget('https://u:p@x.com')).toThrow(/credentials/);
  });
  it('blocks cross-host redirects and HTTPS downgrades', () => {
    expect(isAllowedRedirect('https://example.com/a', 'https://attacker.test/b')).toBe(false);
    expect(isAllowedRedirect('https://example.com/a', 'http://example.com/b')).toBe(false);
    expect(isAllowedRedirect('http://example.com/a', 'https://example.com/b')).toBe(true);
    expect(isAllowedRedirect('http://example.com:8080/a', 'http://example.com:9090/b')).toBe(false);
  });

  it('does not follow a cross-host redirect', async () => {
    const seen: string[] = [];
    await withServer((req, res) => {
      seen.push(req.url ?? '');
      res.writeHead(302, { location: 'http://example.invalid/redirect-target' });
      res.end();
    }, async (url) => {
      const client = new HttpClient({
        timeoutMs: 1000,
        maxBodyBytes: 1024,
        delayMs: 0,
        maxRequests: 5,
        userAgent: 'Kinga-test',
        insecure: false,
        sleep: async () => undefined,
      });
      const result = await client.request(url);
      expect('failed' in result).toBe(false);
      if (!('failed' in result)) expect(result.status).toBe(302);
      expect(seen).toEqual(['/']);
      expect(client.requests).toBe(1);
    });
  });

  it('parses CSP and cookies', () => {
    expect(parseCsp("default-src 'self'; script-src 'unsafe-inline'").get('script-src')).toEqual([
      "'unsafe-inline'",
    ]);
    const c = parseSetCookie('sid=1; Secure; HttpOnly; SameSite=Lax; Path=/');
    expect(c).toMatchObject({ name: 'sid', secure: true, httpOnly: true, sameSite: 'lax' });
  });
});
