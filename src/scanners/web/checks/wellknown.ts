import type { RawFinding } from '../../../core/types.js';
import { webFinding, type WebCheck, type WebContext } from '../context.js';
import { isFailure } from '../http.js';

const SENSITIVE_PATH =
  /(admin|backup|private|internal|secret|config|dump|staging|\.git|database|db\b|passwd|upload)/i;

export const wellKnownChecks: WebCheck = {
  id: 'wellknown',
  title: 'robots.txt and security.txt',
  level: 'passive',
  run(ctx: WebContext): RawFinding[] {
    const out: RawFinding[] = [];
    const robots = ctx.wellKnown.get('/robots.txt');
    if (robots && !isFailure(robots) && robots.status === 200 && !/<html/i.test(robots.body)) {
      const hidden = robots.body
        .split(/\r?\n/)
        .map((l) => /^\s*Disallow:\s*(\S+)/i.exec(l)?.[1])
        .filter((p): p is string => p !== undefined && SENSITIVE_PATH.test(p));
      if (hidden.length > 0) {
        out.push(
          webFinding({
            rule: 'WEB-WKN-001',
            kb: 'robots-sensitive',
            title: 'robots.txt advertises sensitive-looking paths',
            severity: 'info',
            confidence: 'high',
            category: 'information-disclosure',
            target: `${ctx.target.origin}/robots.txt`,
            evidence: `Disallow entries such as ${hidden.slice(0, 5).join(', ')} tell attackers where to look. robots.txt is not access control.`,
          }),
        );
      }
    }
    const sec = ctx.wellKnown.get('/.well-known/security.txt');
    const missing = !sec || isFailure(sec) || sec.status !== 200 || /<html/i.test(sec.body);
    if (missing && !ctx.local && ctx.primary) {
      out.push(
        webFinding({
          rule: 'WEB-WKN-002',
          kb: 'security-txt',
          title: 'No security.txt vulnerability-reporting contact',
          severity: 'info',
          confidence: 'high',
          category: 'process',
          target: `${ctx.target.origin}/.well-known/security.txt`,
          evidence: 'Researchers who find a problem have no published way to tell you (RFC 9116).',
        }),
      );
    }
    return out;
  },
};
