import type { RawFinding } from '../../../core/types.js';
import { isHtml, webFinding, type WebCheck, type WebContext } from '../context.js';
import { header, type Snapshot } from '../http.js';

export function parseCsp(value: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const part of value.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    const name = tokens.shift()?.toLowerCase();
    if (name && !out.has(name)) out.set(name, tokens);
  }
  return out;
}

function hasPasswordField(snapshot: Snapshot): boolean {
  return /<input\b[^>]*\btype\s*=\s*["']?password/i.test(snapshot.body);
}

function isHttps(snapshot: Snapshot): boolean {
  return snapshot.finalUrl.startsWith('https:');
}

function cspFindings(page: Snapshot): RawFinding[] {
  const target = page.finalUrl;
  const out: RawFinding[] = [];
  const enforced = header(page, 'content-security-policy');
  const reportOnly = header(page, 'content-security-policy-report-only');

  if (enforced === undefined) {
    out.push(
      webFinding({
        rule: 'WEB-CSP-001',
        kb: 'csp-missing',
        title: reportOnly
          ? 'Content-Security-Policy is report-only (not enforced)'
          : 'No Content-Security-Policy header',
        severity: reportOnly ? 'low' : 'medium',
        confidence: 'high',
        category: 'headers',
        target,
        evidence: reportOnly
          ? 'Only Content-Security-Policy-Report-Only is sent; browsers do not block anything.'
          : 'The response has no Content-Security-Policy header.',
      }),
    );
    return out;
  }

  const csp = parseCsp(enforced);
  const scriptSrc = csp.get('script-src') ?? csp.get('default-src');
  const strict =
    scriptSrc?.some((s) => /^'(nonce-|sha(256|384|512)-)/i.test(s) || s === "'strict-dynamic'") ??
    false;
  const where = csp.has('script-src') ? 'script-src' : 'default-src';

  if (scriptSrc?.includes("'unsafe-inline'") && !strict) {
    out.push(
      webFinding({
        rule: 'WEB-CSP-002',
        kb: 'csp-weak',
        title: "CSP allows inline scripts ('unsafe-inline')",
        severity: 'medium',
        confidence: 'high',
        category: 'headers',
        target,
        evidence: `${where} contains 'unsafe-inline' and no nonce or hash, so injected inline scripts still run.`,
      }),
    );
  }
  if (scriptSrc?.includes("'unsafe-eval'")) {
    out.push(
      webFinding({
        rule: 'WEB-CSP-003',
        kb: 'csp-weak',
        title: "CSP allows eval() ('unsafe-eval')",
        severity: 'low',
        confidence: 'high',
        category: 'headers',
        target,
        evidence: `${where} contains 'unsafe-eval'.`,
      }),
    );
  }
  const broad = scriptSrc?.filter((s) => s === '*' || /^(https?|data|blob):$/i.test(s)) ?? [];
  if (broad.length > 0) {
    out.push(
      webFinding({
        rule: 'WEB-CSP-004',
        kb: 'csp-weak',
        title: 'CSP allows scripts from almost any origin',
        severity: 'medium',
        confidence: 'high',
        category: 'headers',
        target,
        evidence: `${where} contains ${broad.join(', ')}, which permits scripts from any host or scheme.`,
      }),
    );
  }
  const gaps: string[] = [];
  if (!csp.has('object-src') && !csp.has('default-src')) gaps.push('object-src');
  if (!csp.has('base-uri')) gaps.push('base-uri');
  if (gaps.length > 0) {
    out.push(
      webFinding({
        rule: 'WEB-CSP-005',
        kb: 'csp-weak',
        title: `CSP does not restrict ${gaps.join(' and ')}`,
        severity: 'low',
        confidence: 'high',
        category: 'headers',
        target,
        evidence: `Missing directive(s): ${gaps.join(', ')}. Attackers can use plugins or <base> to get around the script rules.`,
      }),
    );
  }
  return out;
}

export const headerChecks: WebCheck = {
  id: 'headers',
  title: 'HTTP security headers',
  level: 'passive',
  run(ctx: WebContext): RawFinding[] {
    const page = ctx.primary;
    if (!page) return [];
    const out: RawFinding[] = [];
    const target = page.finalUrl;
    const html = isHtml(page);
    const https = isHttps(page);

    if (html) out.push(...cspFindings(page));

    // HSTS applies to HTTPS responses only.
    if (https) {
      const hsts = header(page, 'strict-transport-security');
      if (hsts === undefined) {
        out.push(
          webFinding({
            rule: 'WEB-HSTS-001',
            kb: 'hsts-missing',
            title: 'No Strict-Transport-Security (HSTS) header',
            severity: ctx.local ? 'info' : 'medium',
            confidence: 'high',
            category: 'headers',
            target,
            evidence: 'The HTTPS response has no Strict-Transport-Security header.',
          }),
        );
      } else {
        const maxAge = Number(/max-age\s*=\s*"?(\d+)/i.exec(hsts)?.[1] ?? '0');
        if (maxAge < 15_552_000) {
          out.push(
            webFinding({
              rule: 'WEB-HSTS-002',
              kb: 'hsts-weak',
              title: 'HSTS max-age is too short',
              severity: 'low',
              confidence: 'high',
              category: 'headers',
              target,
              evidence: `Strict-Transport-Security: ${hsts} (max-age ${maxAge}s, recommended at least 31536000).`,
            }),
          );
        }
      }
    }

    if (html || page.contentType !== '') {
      if (header(page, 'x-content-type-options')?.toLowerCase() !== 'nosniff') {
        out.push(
          webFinding({
            rule: 'WEB-HDR-001',
            kb: 'xcto-missing',
            title: 'X-Content-Type-Options: nosniff is missing',
            severity: 'low',
            confidence: 'high',
            category: 'headers',
            target,
            evidence: 'Browsers may MIME-sniff responses and run content as a different type.',
          }),
        );
      }
    }

    if (html) {
      const csp = header(page, 'content-security-policy');
      const framed =
        header(page, 'x-frame-options') !== undefined ||
        (csp !== undefined && parseCsp(csp).has('frame-ancestors'));
      if (!framed) {
        const login = hasPasswordField(page);
        out.push(
          webFinding({
            rule: 'WEB-HDR-002',
            kb: 'clickjacking',
            title: 'Page can be embedded in other sites (clickjacking)',
            severity: login ? 'medium' : 'low',
            confidence: 'high',
            category: 'headers',
            target,
            evidence: `Neither X-Frame-Options nor a CSP frame-ancestors directive is set${login ? ', and the page has a password field' : ''}.`,
          }),
        );
      }
      if (
        header(page, 'referrer-policy') === undefined &&
        !/<meta[^>]+name=["']referrer["']/i.test(page.body)
      ) {
        out.push(
          webFinding({
            rule: 'WEB-HDR-003',
            kb: 'referrer-policy',
            title: 'No Referrer-Policy header',
            severity: 'low',
            confidence: 'high',
            category: 'headers',
            target,
            evidence:
              'Full URLs (including query strings) may be sent to other sites in the Referer header.',
          }),
        );
      }
      if (
        header(page, 'permissions-policy') === undefined &&
        header(page, 'feature-policy') === undefined
      ) {
        out.push(
          webFinding({
            rule: 'WEB-HDR-004',
            kb: 'permissions-policy',
            title: 'No Permissions-Policy header',
            severity: 'info',
            confidence: 'high',
            category: 'headers',
            target,
            evidence:
              'Browser features such as camera, microphone and geolocation are not explicitly restricted.',
          }),
        );
      }
    }

    const xss = header(page, 'x-xss-protection');
    if (xss !== undefined && /^\s*1/.test(xss)) {
      out.push(
        webFinding({
          rule: 'WEB-HDR-005',
          kb: 'xss-protection-header',
          title: 'Deprecated X-XSS-Protection filter is enabled',
          severity: 'info',
          confidence: 'high',
          category: 'headers',
          target,
          evidence: `X-XSS-Protection: ${xss}. The old XSS auditor was removed from browsers and could itself introduce leaks.`,
        }),
      );
    }

    if (html && hasPasswordField(page)) {
      const cache = (header(page, 'cache-control') ?? '').toLowerCase();
      if (!/no-store|private/.test(cache)) {
        out.push(
          webFinding({
            rule: 'WEB-HDR-006',
            kb: 'cache-sensitive',
            title: 'Login page may be cached',
            severity: 'low',
            confidence: 'medium',
            category: 'headers',
            target,
            evidence: `Cache-Control is "${cache === '' ? 'not set' : cache}" on a page with a password field.`,
          }),
        );
      }
    }
    return out;
  },
};
