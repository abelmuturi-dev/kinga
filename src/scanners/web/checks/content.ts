import type { RawFinding } from '../../../core/types.js';
import { findSecretTokens } from '../../../security/redact.js';
import { AdvisoryDb } from '../../deps/advisories.js';
import { isHtml, webFinding, type WebCheck, type WebContext } from '../context.js';
import { detectLibraries, findComments, findForms, findTags, resolveUrl } from '../html.js';
import type { Snapshot } from '../http.js';

const CSRF_FIELD =
  /(csrf|xsrf|authenticity_token|__requestverificationtoken|_token|nonce|_wpnonce)/i;
const COMMENT_SENSITIVE =
  /(password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|token|credential|todo.*(remove|fix|hack)|internal use|staging|debug)/i;

const ERROR_SIGNATURES: Array<{ re: RegExp; label: string }> = [
  { re: /Traceback \(most recent call last\)/, label: 'Python stack trace' },
  { re: /Werkzeug Debugger|The debugger caught an exception/i, label: 'Werkzeug debugger page' },
  { re: /Whitelabel Error Page/, label: 'Spring Boot error page' },
  {
    re: /at (?:[\w$]+\.){2,}[\w$<>]+\((?:[\w]+\.java:\d+|Native Method)\)/,
    label: 'Java stack trace',
  },
  { re: /(?:Fatal error|Parse error|Warning): .{3,200} on line \d+/, label: 'PHP error message' },
  { re: /Server Error in '\/[^']*' Application/, label: 'ASP.NET error page' },
  {
    re: /SQLSTATE\[[0-9A-Z]+\]|You have an error in your SQL syntax|ORA-\d{5}|pg_query\(\)|mysqli?_[a-z_]+\(\)/i,
    label: 'database error message',
  },
  { re: /\bat \S+ \((?:\/|[A-Za-z]:\\)[^)]+:\d+:\d+\)/, label: 'Node.js stack trace' },
  { re: /Stack trace:\s*#0 /, label: 'PHP stack trace' },
  { re: /Rails\.root:|ActionController::RoutingError/, label: 'Rails error page' },
];

function pageHttps(page: Snapshot): boolean {
  return page.finalUrl.startsWith('https:');
}

function clip(text: string, n = 120): string {
  const t = text.replace(/\s+/g, ' ').trim();
  return t.length > n ? `${t.slice(0, n)}…` : t;
}

export const contentChecks: WebCheck = {
  id: 'content',
  title: 'Page content: forms, scripts, leaks',
  level: 'passive',
  run(ctx: WebContext): RawFinding[] {
    const out: RawFinding[] = [];
    const seenRule = new Set<string>();
    const once = (key: string): boolean => {
      if (seenRule.has(key)) return false;
      seenRule.add(key);
      return true;
    };
    const db = new AdvisoryDb();
    const pages = [...ctx.pages, ...(ctx.notFoundProbe ? [ctx.notFoundProbe] : [])];

    for (const page of pages) {
      const body = page.body;
      if (body === '') continue;
      const target = page.finalUrl;
      const https = pageHttps(page);

      // Error messages and stack traces
      for (const sig of ERROR_SIGNATURES) {
        if (sig.re.test(body) && once(`err:${target}`)) {
          out.push(
            webFinding({
              rule: 'WEB-ERR-001',
              kb: 'verbose-errors',
              title: `Detailed error output exposed (${sig.label})`,
              severity: 'medium',
              confidence: 'high',
              category: 'information-disclosure',
              target,
              evidence: `The response body contains a ${sig.label}. Internals such as file paths, queries and library versions help attackers.`,
            }),
          );
        }
      }

      // Directory listing
      if (/<title>\s*Index of \//i.test(body) && once('dirlist')) {
        out.push(
          webFinding({
            rule: 'WEB-ERR-002',
            kb: 'directory-listing',
            title: 'Directory listing is enabled',
            severity: 'medium',
            confidence: 'high',
            category: 'information-disclosure',
            target,
            evidence: 'The page is an automatic "Index of /" listing that exposes file names.',
          }),
        );
      }

      // Secrets sitting in the page or inline scripts
      const secrets = findSecretTokens(body);
      if (secrets.length > 0 && once(`secret:${target}`)) {
        const first = secrets[0];
        out.push(
          webFinding({
            rule: 'WEB-SEC-001',
            kb: 'secret-in-page',
            title: 'Credential-shaped secret delivered to every visitor',
            severity: first?.kind === 'private-key' ? 'critical' : 'high',
            confidence: 'medium',
            category: 'secrets',
            target,
            evidence: `${first?.preview ?? 'token'} found in the response body${secrets.length > 1 ? ` (+${secrets.length - 1} more)` : ''}; value not shown.`,
            verified: false,
            verification:
              'The text matches a known credential format. Kinga never tests whether a secret is live.',
          }),
        );
      }

      if (!isHtml(page)) continue;

      // Forms
      for (const form of findForms(body)) {
        const action =
          form.action === '' ? new URL(page.finalUrl) : resolveUrl(form.action, page.finalUrl);
        const hasPassword = form.inputs.some(
          (i) => (i.attrs['type'] ?? '').toLowerCase() === 'password',
        );
        if (hasPassword && !https && once(`pwhttp:${target}`)) {
          out.push(
            webFinding({
              rule: 'WEB-FRM-001',
              kb: 'password-over-http',
              title: 'Password form served over unencrypted HTTP',
              severity: ctx.local ? 'low' : 'high',
              confidence: 'high',
              category: 'forms',
              target,
              evidence:
                'A password field is delivered and submitted without TLS, so credentials cross the network in clear text.',
            }),
          );
        }
        if (https && action?.protocol === 'http:' && once(`formhttp:${target}`)) {
          out.push(
            webFinding({
              rule: 'WEB-FRM-002',
              kb: 'insecure-form-action',
              title: 'HTTPS page submits a form to an HTTP address',
              severity: hasPassword ? 'high' : 'medium',
              confidence: 'high',
              category: 'forms',
              target,
              evidence: `Form action is ${clip(form.action, 80)}.`,
            }),
          );
        }
        if (form.method === 'get' && hasPassword && once(`pwget:${target}`)) {
          out.push(
            webFinding({
              rule: 'WEB-FRM-003',
              kb: 'password-over-http',
              title: 'Password submitted with GET (ends up in URLs and logs)',
              severity: 'high',
              confidence: 'high',
              category: 'forms',
              target,
              evidence: 'A form containing a password field uses method="get".',
            }),
          );
        }
        const hasToken = form.inputs.some((i) => CSRF_FIELD.test(i.attrs['name'] ?? ''));
        if (form.method === 'post' && !hasToken && once(`csrf:${target}`)) {
          out.push(
            webFinding({
              rule: 'WEB-FRM-004',
              kb: 'csrf-token-missing',
              title: 'POST form without a visible anti-CSRF token',
              severity: 'low',
              confidence: 'low',
              category: 'forms',
              target,
              evidence: 'No hidden field with a CSRF-style name was found in a POST form.',
              verified: false,
              verification:
                'Frameworks can also protect forms with headers, SameSite cookies or tokens added by JavaScript, which this check cannot see.',
            }),
          );
        }
      }

      // Scripts and stylesheets
      const scripts = findTags(body, 'script').filter((t) => t.attrs['src']);
      const sheets = findTags(body, 'link').filter(
        (t) => (t.attrs['rel'] ?? '').toLowerCase().includes('stylesheet') && t.attrs['href'],
      );
      const resources = [
        ...scripts.map((t) => ({ kind: 'script', url: t.attrs['src'] ?? '', tag: t })),
        ...sheets.map((t) => ({ kind: 'stylesheet', url: t.attrs['href'] ?? '', tag: t })),
      ];
      const urls: string[] = [];
      for (const r of resources) {
        const u = resolveUrl(r.url, page.finalUrl);
        if (!u) continue;
        urls.push(u.toString());
        if (https && u.protocol === 'http:' && once(`mixed:${u.toString()}`)) {
          out.push(
            webFinding({
              rule: 'WEB-MIX-001',
              kb: 'mixed-content',
              title: `Insecure ${r.kind} loaded on an HTTPS page`,
              severity: 'medium',
              confidence: 'high',
              category: 'transport',
              target,
              evidence: `${clip(u.toString(), 100)} is loaded over HTTP; browsers block or warn, and an attacker can swap it.`,
            }),
          );
        }
        if (
          u.host !== new URL(page.finalUrl).host &&
          r.tag.attrs['integrity'] === undefined &&
          r.kind === 'script' &&
          once(`sri:${u.host}`)
        ) {
          out.push(
            webFinding({
              rule: 'WEB-SRI-001',
              kb: 'sri-missing',
              title: `Third-party script from ${u.host} has no Subresource Integrity hash`,
              severity: 'low',
              confidence: 'high',
              category: 'supply-chain',
              target,
              evidence: `<script src="${clip(u.toString(), 100)}"> has no integrity attribute; if that host is compromised, its code runs on your page.`,
            }),
          );
        }
      }

      // Known-vulnerable front-end libraries (from versions in script URLs)
      for (const lib of detectLibraries(urls)) {
        for (const hit of db.lookup('npm', lib.name, lib.version)) {
          if (!once(`lib:${lib.name}@${lib.version}:${hit.advisory.id}`)) continue;
          out.push(
            webFinding({
              rule: 'WEB-LIB-001',
              kb: 'vulnerable-js-library',
              title: `Vulnerable front-end library: ${lib.name} ${lib.version}`,
              severity: hit.advisory.severity,
              confidence: 'high',
              category: 'outdated-components',
              target,
              evidence: `${hit.advisory.id}: ${hit.advisory.summary}. Loaded from ${clip(lib.source, 90)}. Fixed in ${hit.fixedIn}.`,
              verified: false,
              verification:
                'The version was read from the script URL; a self-hosted file could have been patched without changing its name.',
              facts: {
                package: lib.name,
                version: lib.version,
                fixedIn: hit.fixedIn,
                advisory: hit.advisory.id,
              },
            }),
          );
        }
      }

      // Comments that leak information
      for (const comment of findComments(body)) {
        if (COMMENT_SENSITIVE.test(comment) && once(`comment:${target}`)) {
          out.push(
            webFinding({
              rule: 'WEB-CMT-001',
              kb: 'html-comment-leak',
              title: 'HTML comment contains sensitive-sounding text',
              severity: 'low',
              confidence: 'low',
              category: 'information-disclosure',
              target,
              evidence: `<!-- ${clip(comment, 100)} -->`,
              verified: false,
              verification:
                'Keyword match on a comment; read it to judge whether it really leaks anything.',
            }),
          );
        }
      }

      if (/\/\/[#@]\s*sourceMappingURL=/.test(body) && once(`map:${target}`)) {
        out.push(
          webFinding({
            rule: 'WEB-MAP-001',
            kb: 'sourcemap-exposed',
            title: 'Inline source map reference in production page',
            severity: 'info',
            confidence: 'medium',
            category: 'information-disclosure',
            target,
            evidence:
              'A sourceMappingURL comment was found; published source maps reveal your original source code.',
          }),
        );
      }
    }
    return out;
  },
};
