import type { RawFinding } from '../../../core/types.js';
import { webFinding, type WebCheck, type WebContext } from '../context.js';

export interface ParsedCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: 'strict' | 'lax' | 'none' | null;
  path: string | null;
  domain: string | null;
  maxAge: number | null;
  hasExpires: boolean;
}

export function parseSetCookie(raw: string): ParsedCookie | null {
  const parts = raw.split(';').map((p) => p.trim());
  const first = parts.shift() ?? '';
  const eq = first.indexOf('=');
  if (eq <= 0) return null;
  const cookie: ParsedCookie = {
    name: first.slice(0, eq).trim(),
    secure: false,
    httpOnly: false,
    sameSite: null,
    path: null,
    domain: null,
    maxAge: null,
    hasExpires: false,
  };
  for (const part of parts) {
    const [k, ...rest] = part.split('=');
    const key = (k ?? '').trim().toLowerCase();
    const value = rest.join('=').trim();
    if (key === 'secure') cookie.secure = true;
    else if (key === 'httponly') cookie.httpOnly = true;
    else if (key === 'samesite') {
      const v = value.toLowerCase();
      cookie.sameSite = v === 'strict' || v === 'lax' || v === 'none' ? v : null;
    } else if (key === 'path') cookie.path = value;
    else if (key === 'domain') cookie.domain = value;
    else if (key === 'max-age') cookie.maxAge = Number.parseInt(value, 10);
    else if (key === 'expires') cookie.hasExpires = true;
  }
  return cookie;
}

const SESSION_NAME = /(sess|sid\b|auth|token|jwt|login|remember|identity|\buser)/i;
const CSRF_NAME = /(csrf|xsrf)/i;

export function isSessionCookie(name: string): boolean {
  return SESSION_NAME.test(name) && !CSRF_NAME.test(name);
}

export const cookieChecks: WebCheck = {
  id: 'cookies',
  title: 'Cookie attributes',
  level: 'passive',
  run(ctx: WebContext): RawFinding[] {
    const out: RawFinding[] = [];
    const seen = new Set<string>();
    for (const page of ctx.pages) {
      const https = page.finalUrl.startsWith('https:');
      for (const raw of page.setCookies) {
        const cookie = parseSetCookie(raw);
        if (!cookie || seen.has(cookie.name)) continue;
        seen.add(cookie.name);
        const session = isSessionCookie(cookie.name);
        const target = page.finalUrl;

        if (https && !cookie.secure) {
          out.push(
            webFinding({
              rule: 'WEB-CKE-001',
              kb: 'cookie-secure',
              title: `Cookie "${cookie.name}" is missing the Secure flag`,
              severity: session ? 'medium' : 'low',
              confidence: 'high',
              category: 'cookies',
              target,
              evidence: `Set-Cookie for "${cookie.name}" has no Secure attribute, so browsers may send it over plain HTTP.`,
              facts: { cookie: cookie.name, session },
            }),
          );
        }
        if (!cookie.httpOnly && !CSRF_NAME.test(cookie.name)) {
          out.push(
            webFinding({
              rule: 'WEB-CKE-002',
              kb: 'cookie-httponly',
              title: `Cookie "${cookie.name}" is readable by JavaScript (no HttpOnly)`,
              severity: session ? 'medium' : 'low',
              confidence: 'high',
              category: 'cookies',
              target,
              evidence: `Set-Cookie for "${cookie.name}" has no HttpOnly attribute, so any script injected into the page can read it.`,
              facts: { cookie: cookie.name, session },
            }),
          );
        }
        if (cookie.sameSite === null) {
          out.push(
            webFinding({
              rule: 'WEB-CKE-003',
              kb: 'cookie-samesite',
              title: `Cookie "${cookie.name}" has no SameSite attribute`,
              severity: 'low',
              confidence: 'high',
              category: 'cookies',
              target,
              evidence: `Set-Cookie for "${cookie.name}" has no SameSite attribute; browsers fall back to their default, which differs between versions.`,
              facts: { cookie: cookie.name, session },
            }),
          );
        } else if (cookie.sameSite === 'none' && !cookie.secure) {
          out.push(
            webFinding({
              rule: 'WEB-CKE-004',
              kb: 'cookie-samesite',
              title: `Cookie "${cookie.name}" uses SameSite=None without Secure`,
              severity: 'medium',
              confidence: 'high',
              category: 'cookies',
              target,
              evidence: 'SameSite=None requires Secure; browsers reject or downgrade such cookies.',
            }),
          );
        }
        if (
          /^__Host-/.test(cookie.name) &&
          (!cookie.secure || cookie.path !== '/' || cookie.domain)
        ) {
          out.push(
            webFinding({
              rule: 'WEB-CKE-005',
              kb: 'cookie-prefix',
              title: `Cookie "${cookie.name}" breaks the __Host- prefix rules`,
              severity: 'low',
              confidence: 'high',
              category: 'cookies',
              target,
              evidence: '__Host- cookies must be Secure, have Path=/ and no Domain attribute.',
            }),
          );
        }
      }
    }
    return out;
  },
};
