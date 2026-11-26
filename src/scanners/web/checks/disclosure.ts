import type { RawFinding } from '../../../core/types.js';
import { compareVersions, parseVersion } from '../../deps/version.js';
import { webFinding, type WebCheck, type WebContext } from '../context.js';
import { header } from '../http.js';

/** PHP release lines and the date security support ended. */
const PHP_EOL: Record<string, string> = {
  '7.4': '2022-11-28',
  '8.0': '2023-11-26',
  '8.1': '2025-12-31',
  '8.2': '2026-12-31',
  '8.3': '2027-12-31',
};

interface Product {
  label: string;
  version: string;
  source: string;
}

function products(
  server: string | undefined,
  powered: string | undefined,
  aspnet: string | undefined,
): Product[] {
  const out: Product[] = [];
  const scan = (value: string | undefined, source: string): void => {
    if (!value) return;
    for (const m of value.matchAll(/([A-Za-z][\w.-]*)\/(\d+(?:\.\d+)+[a-z]?)/g)) {
      if (m[1] && m[2]) out.push({ label: m[1], version: m[2], source });
    }
  };
  scan(server, 'Server');
  scan(powered, 'X-Powered-By');
  if (aspnet) out.push({ label: 'ASP.NET', version: aspnet, source: 'X-AspNet-Version' });
  return out;
}

function eolReason(p: Product, now: Date): string | null {
  const v = parseVersion(p.version);
  if (!v) return null;
  const name = p.label.toLowerCase();
  if (name === 'php') {
    const line = `${v[0] ?? 0}.${v[1] ?? 0}`;
    if ((v[0] ?? 0) < 7) return `PHP ${p.version} is far past end of life`;
    const eol = PHP_EOL[line];
    if (eol && now.getTime() > new Date(eol).getTime())
      return `PHP ${line} reached end of security support on ${eol}`;
    return null;
  }
  if (name === 'apache' && compareVersions(v, [2, 4]) < 0)
    return `Apache ${p.version} is an unsupported release line (2.2 ended in 2017)`;
  if (name === 'microsoft-iis' && compareVersions(v, [8, 5]) <= 0)
    return `IIS ${p.version} runs on Windows Server releases that no longer receive security updates`;
  if (name === 'openssl' && compareVersions(v, [3, 0]) < 0)
    return `OpenSSL ${p.version} is end of life (1.1.1 ended in September 2023)`;
  if (name === 'python' && (v[0] ?? 0) < 3)
    return `Python ${p.version} is end of life (2.x ended in 2020)`;
  if (name === 'asp.net' && /^[123]\./.test(p.version))
    return `.NET runtime ${p.version} is end of life`;
  return null;
}

export const disclosureChecks: WebCheck = {
  id: 'disclosure',
  title: 'Technology disclosure and outdated software',
  level: 'passive',
  run(ctx: WebContext): RawFinding[] {
    const page = ctx.primary;
    if (!page) return [];
    const out: RawFinding[] = [];
    const target = page.finalUrl;
    const server = header(page, 'server');
    const powered = header(page, 'x-powered-by');
    const aspnet = header(page, 'x-aspnet-version') ?? header(page, 'x-aspnetmvc-version');

    const disclosed: string[] = [];
    if (server && /\d/.test(server)) disclosed.push(`Server: ${server}`);
    if (powered) disclosed.push(`X-Powered-By: ${powered}`);
    if (aspnet) disclosed.push(`X-AspNet-Version: ${aspnet}`);
    if (disclosed.length > 0) {
      out.push(
        webFinding({
          rule: 'WEB-INF-001',
          kb: 'info-disclosure-headers',
          title: 'Server software and version are disclosed',
          severity: 'low',
          confidence: 'high',
          category: 'information-disclosure',
          target,
          evidence: disclosed.join('; '),
        }),
      );
    }

    for (const p of products(server, powered, aspnet)) {
      const reason = eolReason(p, ctx.now);
      if (reason) {
        out.push(
          webFinding({
            rule: 'WEB-INF-002',
            kb: 'eol-software',
            title: `Outdated or end-of-life software advertised: ${p.label} ${p.version}`,
            severity: 'medium',
            confidence: 'medium',
            category: 'outdated-components',
            target,
            evidence: `${p.source} header reports ${p.label}/${p.version}. ${reason}.`,
            verified: false,
            verification:
              'Based on a version string the server chose to send; distributions often back-port fixes and the header can be wrong or spoofed.',
          }),
        );
      }
    }
    const apache = /Apache\/(2\.4\.(49|50))\b/.exec(server ?? '');
    if (apache?.[1]) {
      out.push(
        webFinding({
          rule: 'WEB-INF-003',
          kb: 'known-vulnerable-server',
          title: `Apache ${apache[1]} has known critical vulnerabilities`,
          severity: 'high',
          confidence: 'medium',
          category: 'outdated-components',
          target,
          evidence: `Server: ${server}. Apache 2.4.49 and 2.4.50 are affected by path traversal / remote code execution (CVE-2021-41773, CVE-2021-42013).`,
          verified: false,
          verification:
            'Based on the advertised version only; the vulnerability itself was not exercised.',
        }),
      );
    }

    if (
      !ctx.local &&
      server &&
      /^(Werkzeug|WSGIServer|SimpleHTTP|BaseHTTP|Python\/|uvicorn$)/i.test(server) &&
      !/gunicorn|nginx|apache/i.test(server)
    ) {
      out.push(
        webFinding({
          rule: 'WEB-INF-004',
          kb: 'dev-server-exposed',
          title: 'A development web server appears to be serving production traffic',
          severity: 'medium',
          confidence: 'medium',
          category: 'misconfiguration',
          target,
          evidence: `Server: ${server}. Framework development servers are not hardened for the internet.`,
          verified: false,
          verification: 'Inferred from the Server header.',
        }),
      );
    }

    const gen = /<meta[^>]+name=["']generator["'][^>]*content=["']([^"']+)["']/i.exec(
      page.body,
    )?.[1];
    if (gen && /\d/.test(gen)) {
      out.push(
        webFinding({
          rule: 'WEB-INF-005',
          kb: 'info-disclosure-headers',
          title: 'Page advertises its CMS or generator version',
          severity: 'info',
          confidence: 'high',
          category: 'information-disclosure',
          target,
          evidence: `<meta name="generator" content="${gen.slice(0, 80)}">`,
        }),
      );
    }
    return out;
  },
};
