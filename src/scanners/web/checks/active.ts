import type { RawFinding, Severity } from '../../../core/types.js';
import { webFinding, type WebCheck, type WebContext } from '../context.js';
import { BudgetExceeded, header, isFailure, type Snapshot } from '../http.js';

const PROBE_ORIGIN = 'https://kinga-cors-probe.invalid';

/** Sends harmless requests with a foreign Origin header and reads how the server answers. */
export const corsCheck: WebCheck = {
  id: 'cors',
  title: 'CORS policy',
  level: 'active',
  async run(ctx: WebContext): Promise<RawFinding[]> {
    const page = ctx.primary;
    if (!page) return [];
    const out: RawFinding[] = [];
    const url = page.finalUrl;
    for (const origin of [PROBE_ORIGIN, 'null']) {
      const res = await ctx.client.request(url, { headers: { origin }, follow: false });
      if (isFailure(res)) return out;
      const acao = header(res, 'access-control-allow-origin');
      const acac = header(res, 'access-control-allow-credentials')?.toLowerCase() === 'true';
      if (acao === undefined) continue;
      const reflected = acao === origin;
      if (reflected && acac) {
        out.push(
          webFinding({
            rule: 'WEB-COR-001',
            kb: 'cors-misconfig',
            title:
              origin === 'null'
                ? 'CORS trusts the "null" origin and allows credentials'
                : 'CORS reflects any Origin and allows credentials',
            severity: 'high',
            confidence: 'high',
            category: 'cors',
            target: url,
            evidence: `Origin: ${origin} was answered with Access-Control-Allow-Origin: ${acao} and Access-Control-Allow-Credentials: true, so any website can read authenticated responses.`,
          }),
        );
        return out;
      }
      if (reflected) {
        out.push(
          webFinding({
            rule: 'WEB-COR-002',
            kb: 'cors-misconfig',
            title: 'CORS reflects arbitrary origins',
            severity: 'low',
            confidence: 'high',
            category: 'cors',
            target: url,
            evidence: `Access-Control-Allow-Origin echoed the untrusted origin ${origin}. Without credentials the impact is limited to non-public data reachable without cookies.`,
          }),
        );
        return out;
      }
      if (acao === '*') {
        out.push(
          webFinding({
            rule: 'WEB-COR-003',
            kb: 'cors-misconfig',
            title: 'CORS allows every origin (*)',
            severity: acac ? 'medium' : 'low',
            confidence: 'high',
            category: 'cors',
            target: url,
            evidence:
              'Access-Control-Allow-Origin: *. Fine for public data, wrong for anything private.',
          }),
        );
        return out;
      }
    }
    return out;
  },
};

export const methodsCheck: WebCheck = {
  id: 'methods',
  title: 'HTTP methods',
  level: 'active',
  async run(ctx: WebContext): Promise<RawFinding[]> {
    const page = ctx.primary;
    if (!page) return [];
    const res = await ctx.client.request(page.finalUrl, { method: 'OPTIONS', follow: false });
    if (isFailure(res)) return [];
    const allow = `${header(res, 'allow') ?? ''},${header(res, 'access-control-allow-methods') ?? ''}`;
    const methods = new Set(
      allow
        .split(',')
        .map((m) => m.trim().toUpperCase())
        .filter(Boolean),
    );
    const risky = ['TRACE', 'TRACK', 'PUT', 'DELETE', 'CONNECT'].filter((m) => methods.has(m));
    if (risky.length === 0) return [];
    const trace = risky.includes('TRACE') || risky.includes('TRACK');
    return [
      webFinding({
        rule: 'WEB-MTH-001',
        kb: 'http-methods',
        title: `Risky HTTP methods advertised: ${risky.join(', ')}`,
        severity: trace ? 'low' : 'info',
        confidence: 'medium',
        category: 'misconfiguration',
        target: page.finalUrl,
        evidence: `OPTIONS answered with an Allow list that includes ${risky.join(', ')}. This only matters if the application actually honours them without authorization.`,
        verified: false,
        verification: 'Read from the OPTIONS response; the methods themselves were not exercised.',
      }),
    ];
  },
};

interface Probe {
  path: string;
  rule: string;
  kb: string;
  title: string;
  severity: Severity;
  /** Returns evidence text when the body proves the resource really is exposed, otherwise null. */
  test(res: Snapshot): string | null;
}

const KEY_VALUE_LINES = /^[A-Za-z_][A-Za-z0-9_.]{2,}\s*=\s*\S+/gm;

function textLooksLikeHtml(body: string): boolean {
  return /^\s*<(!doctype|html|head|body)/i.test(body);
}

const PROBES: Probe[] = [
  {
    path: '/.git/HEAD',
    rule: 'WEB-EXP-001',
    kb: 'exposed-git',
    title: 'Git repository is publicly downloadable',
    severity: 'high',
    test: (r) =>
      /^ref:\s*refs\/heads\/\S+/m.test(r.body)
        ? 'GET /.git/HEAD returned a valid Git HEAD file; the entire source history can be reconstructed.'
        : null,
  },
  {
    path: '/.env',
    rule: 'WEB-EXP-002',
    kb: 'exposed-env',
    title: 'Environment file (.env) is publicly readable',
    severity: 'critical',
    test: (r) => {
      if (textLooksLikeHtml(r.body)) return null;
      const n = (r.body.match(KEY_VALUE_LINES) ?? []).length;
      return n >= 2
        ? `GET /.env returned ${n} KEY=VALUE lines. Contents were inspected in memory only and are not recorded.`
        : null;
    },
  },
  {
    path: '/phpinfo.php',
    rule: 'WEB-EXP-003',
    kb: 'exposed-debug',
    title: 'phpinfo() page is publicly accessible',
    severity: 'high',
    test: (r) =>
      /phpinfo\(\)|PHP Version\s*<\/?[a-z]/i.test(r.body) && /System|Configuration/.test(r.body)
        ? 'The page prints PHP configuration, paths, loaded modules and environment details.'
        : null,
  },
  {
    path: '/server-status',
    rule: 'WEB-EXP-004',
    kb: 'exposed-debug',
    title: 'Apache server-status page is publicly accessible',
    severity: 'medium',
    test: (r) =>
      /Apache Server Status for/i.test(r.body)
        ? 'The status page lists live requests, client IP addresses and URLs.'
        : null,
  },
  {
    path: '/actuator/env',
    rule: 'WEB-EXP-005',
    kb: 'exposed-debug',
    title: 'Spring Boot Actuator /env endpoint is exposed',
    severity: 'high',
    test: (r) =>
      /"propertySources"|"activeProfiles"/.test(r.body)
        ? 'The endpoint returns application configuration, which commonly includes secrets.'
        : null,
  },
  {
    path: '/actuator',
    rule: 'WEB-EXP-006',
    kb: 'exposed-debug',
    title: 'Spring Boot Actuator index is exposed',
    severity: 'medium',
    test: (r) =>
      /"_links"/.test(r.body) && /"(env|heapdump|beans|mappings|configprops)"/.test(r.body)
        ? 'The actuator index advertises sensitive management endpoints.'
        : null,
  },
  {
    path: '/console',
    rule: 'WEB-EXP-007',
    kb: 'exposed-debug',
    title: 'Interactive debugger console is exposed',
    severity: 'critical',
    test: (r) =>
      /Werkzeug|Interactive Console|debugger.*console/i.test(r.body) && /console/i.test(r.body)
        ? 'A debug console that executes code on the server is reachable.'
        : null,
  },
  {
    path: '/wp-config.php.bak',
    rule: 'WEB-EXP-008',
    kb: 'exposed-backup',
    title: 'WordPress configuration backup is downloadable',
    severity: 'critical',
    test: (r) =>
      /DB_PASSWORD|DB_NAME/.test(r.body) ? 'The backup file contains database settings.' : null,
  },
  {
    path: '/dump.sql',
    rule: 'WEB-EXP-009',
    kb: 'exposed-backup',
    title: 'Database dump is downloadable',
    severity: 'critical',
    test: (r) =>
      /CREATE TABLE|INSERT INTO|DROP TABLE/i.test(r.body)
        ? 'The file looks like a SQL dump.'
        : null,
  },
  {
    path: '/backup.sql',
    rule: 'WEB-EXP-010',
    kb: 'exposed-backup',
    title: 'Database backup is downloadable',
    severity: 'critical',
    test: (r) =>
      /CREATE TABLE|INSERT INTO|DROP TABLE/i.test(r.body)
        ? 'The file looks like a SQL dump.'
        : null,
  },
  {
    path: '/.svn/entries',
    rule: 'WEB-EXP-011',
    kb: 'exposed-git',
    title: 'Subversion metadata is publicly accessible',
    severity: 'medium',
    test: (r) =>
      /^\d+\s*\n\s*dir\b/m.test(r.body)
        ? 'SVN working-copy metadata reveals file names and paths.'
        : null,
  },
  {
    path: '/elmah.axd',
    rule: 'WEB-EXP-012',
    kb: 'exposed-debug',
    title: 'ELMAH error log is publicly accessible',
    severity: 'high',
    test: (r) =>
      /Error Log for/i.test(r.body)
        ? 'Application error logs with stack traces are readable.'
        : null,
  },
  {
    path: '/phpmyadmin/',
    rule: 'WEB-EXP-013',
    kb: 'exposed-admin-tool',
    title: 'phpMyAdmin is reachable from the internet',
    severity: 'medium',
    test: (r) =>
      /phpMyAdmin/i.test(r.body)
        ? 'A database administration login page is exposed to everyone.'
        : null,
  },
  {
    path: '/docker-compose.yml',
    rule: 'WEB-EXP-014',
    kb: 'exposed-config-file',
    title: 'docker-compose.yml is publicly readable',
    severity: 'medium',
    test: (r) =>
      /^\s*services\s*:/m.test(r.body)
        ? 'Infrastructure layout and possibly credentials are readable.'
        : null,
  },
  {
    path: '/package.json',
    rule: 'WEB-EXP-015',
    kb: 'exposed-config-file',
    title: 'package.json is publicly readable',
    severity: 'low',
    test: (r) =>
      /"(dependencies|devDependencies|scripts)"\s*:/.test(r.body)
        ? 'Dependency names and versions help attackers pick known exploits.'
        : null,
  },
  {
    path: '/.npmrc',
    rule: 'WEB-EXP-016',
    kb: 'exposed-env',
    title: '.npmrc is publicly readable',
    severity: 'high',
    test: (r) =>
      /_authToken|:_password|registry\s*=/.test(r.body) && !textLooksLikeHtml(r.body)
        ? 'A package-registry configuration file (which can hold auth tokens) is readable.'
        : null,
  },
  {
    path: '/swagger.json',
    rule: 'WEB-EXP-017',
    kb: 'exposed-api-docs',
    title: 'API specification is publicly readable',
    severity: 'info',
    test: (r) =>
      /"(swagger|openapi)"\s*:/.test(r.body)
        ? 'The full list of API routes and parameters is public. Fine for public APIs, risky for internal ones.'
        : null,
  },
  {
    path: '/openapi.json',
    rule: 'WEB-EXP-018',
    kb: 'exposed-api-docs',
    title: 'OpenAPI document is publicly readable',
    severity: 'info',
    test: (r) =>
      /"openapi"\s*:/.test(r.body)
        ? 'The full list of API routes and parameters is public. Fine for public APIs, risky for internal ones.'
        : null,
  },
];

export const exposureCheck: WebCheck = {
  id: 'exposure',
  title: 'Sensitive file and endpoint exposure',
  level: 'active',
  async run(ctx: WebContext): Promise<RawFinding[]> {
    const out: RawFinding[] = [];
    const origin = ctx.target.origin;
    for (const probe of PROBES) {
      let res;
      try {
        res = await ctx.client.request(`${origin}${probe.path}`, {
          follow: false,
          peekBytes: 32_768,
        });
      } catch (error) {
        if (error instanceof BudgetExceeded) {
          ctx.notes.push('Request budget reached; remaining exposure probes were skipped.');
          break;
        }
        throw error;
      }
      if (isFailure(res) || res.status !== 200) continue;
      // A catch-all page that answers every path identically proves nothing.
      if (
        ctx.notFoundProbe &&
        ctx.notFoundProbe.status === 200 &&
        ctx.notFoundProbe.body === res.body
      )
        continue;
      const evidence = probe.test(res);
      if (evidence === null) continue;
      out.push(
        webFinding({
          rule: probe.rule,
          kb: probe.kb,
          title: probe.title,
          severity: probe.severity,
          confidence: 'high',
          category: 'exposure',
          target: `${origin}${probe.path}`,
          evidence,
        }),
      );
    }
    return out;
  },
};
