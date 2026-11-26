import type { Effort, Finding, FixStep, Insight, Severity } from '../core/types.js';
import { SEVERITY_RANK } from '../core/types.js';
import { effortRank, TOPICS } from './advisor.js';

const has = (findings: readonly Finding[], pred: (f: Finding) => boolean): Finding[] =>
  findings.filter(pred);
const kb =
  (...keys: string[]) =>
  (f: Finding): boolean =>
    keys.includes(f.kb);

/**
 * Looks for combinations of findings that are worse together than apart. Each rule explains the
 * attack path in plain language, which is what a person triaging a long list needs most.
 */
export function deriveInsights(findings: readonly Finding[]): Insight[] {
  const out: Insight[] = [];
  const add = (
    id: string,
    title: string,
    severity: Severity,
    narrative: string,
    group: Finding[],
    recommendation: string,
  ): void => {
    if (group.length === 0) return;
    out.push({
      id,
      title,
      severity,
      narrative,
      findingIds: group.map((f) => f.id),
      recommendation,
    });
  };

  // 1. Credentials exposed through more than one door.
  const exposedSecrets = has(
    findings,
    kb('exposed-env', 'exposed-git', 'exposed-backup', 'secret-in-page'),
  );
  const codeSecrets = has(
    findings,
    kb('hardcoded-secret', 'secret-file-committed', 'docker-secret-layer'),
  );
  if (exposedSecrets.length > 0) {
    add(
      'INS-001',
      'Credentials are probably already compromised',
      'critical',
      'A file or page that contains secrets is reachable by anyone on the internet, and automated scanners request these paths constantly. Treat every secret in it as stolen, not as "at risk".',
      [...exposedSecrets, ...codeSecrets],
      'Rotate the credentials first (database, API keys, signing secrets), then close the exposure, then check provider and server logs for use you do not recognise.',
    );
  } else if (codeSecrets.length >= 2) {
    add(
      'INS-002',
      'Secrets are spread through the code base',
      'high',
      'Several credentials sit in source, config or images. Each copy of the repository, CI log or image is another place they can leak from.',
      codeSecrets,
      'Move all secrets to a secret manager or environment variables in one pass, rotate them, and add a secret scanner to CI so new ones are blocked.',
    );
  }

  // 2. Credentials over an unencrypted channel.
  const clearText = has(
    findings,
    kb(
      'no-https',
      'password-over-http',
      'https-downgrade',
      'insecure-form-action',
      'http-no-redirect',
    ),
  );
  if (has(findings, kb('password-over-http', 'no-https')).length > 0 && clearText.length >= 2) {
    add(
      'INS-003',
      'Logins can be intercepted on the network',
      'high',
      'The site serves login or account pages without enforced HTTPS. Anyone on the same Wi-Fi, or anywhere along the route, can read passwords and session cookies or alter the page.',
      clearText,
      'Enable HTTPS everywhere, redirect HTTP to HTTPS, send HSTS, and mark cookies Secure. This is usually a one-hour change.',
    );
  }

  // 3. XSS exposure chain.
  const xss = has(
    findings,
    kb(
      'xss-dom',
      'xss-framework-bypass',
      'xss-reflected',
      'vulnerable-js-library',
      'mixed-content',
      'sri-missing',
    ),
  );
  const noCsp = has(findings, kb('csp-missing', 'csp-weak'));
  const openCookies = has(findings, kb('cookie-httponly'));
  if (xss.length > 0 && (noCsp.length > 0 || openCookies.length > 0)) {
    add(
      'INS-004',
      'A script-injection bug would lead straight to account takeover',
      xss.some((f) => f.severity === 'high' || f.severity === 'critical') ? 'high' : 'medium',
      'There are places where untrusted content can reach the page, and nothing in the browser would contain the damage: no enforced Content-Security-Policy and/or cookies that scripts can read. A single injected script could copy the session cookie and log in as the victim.',
      [...xss, ...noCsp, ...openCookies],
      'Fix the injection points, then add a strict CSP and HttpOnly cookies so one mistake does not become a takeover.',
    );
  }

  // 4. Injection that is easy to exploit because errors are verbose.
  const injection = has(
    findings,
    kb('sql-injection', 'nosql-injection', 'command-injection', 'ssti', 'code-eval'),
  );
  const verbose = has(findings, kb('verbose-errors', 'verbose-errors-code', 'debug-enabled'));
  if (injection.length > 0 && verbose.length > 0) {
    add(
      'INS-005',
      'Injection flaws are easier to exploit because errors reveal internals',
      'high',
      'Detailed error output or debug mode tells an attacker exactly how their input is being interpreted (query text, file paths, library versions), which turns blind guessing into a quick, guided attack.',
      [...injection, ...verbose],
      'Fix the injectable code paths first; then switch to generic error pages and move details to server logs.',
    );
  }

  // 5. Weak or missing session/CSRF defences.
  const csrf = has(findings, kb('csrf-token-missing', 'auth-disabled'));
  const samesite = has(findings, kb('cookie-samesite'));
  if (csrf.length > 0 && samesite.length > 0) {
    add(
      'INS-006',
      'Cross-site request forgery protection is thin',
      'medium',
      "State-changing forms or endpoints lack anti-CSRF tokens and the cookies have no SameSite attribute, so another website may be able to make a logged-in user's browser perform actions.",
      [...csrf, ...samesite],
      'Enable the framework CSRF protection and set SameSite=Lax (or Strict) on session cookies.',
    );
  }

  // 6. Open CORS with credentials or cookies.
  const cors = has(findings, kb('cors-misconfig', 'cors-code'));
  if (cors.some((f) => f.severity === 'high') && has(findings, kb('cookie-samesite')).length > 0) {
    add(
      'INS-007',
      "Another website may be able to read signed-in users' data",
      'high',
      "The API trusts arbitrary origins with credentials, and cookies are not restricted to same-site use, so a malicious page can fetch private responses using the visitor's login.",
      [...cors, ...has(findings, kb('cookie-samesite'))],
      'Allow only an explicit origin list, never reflect Origin with credentials, and set SameSite on cookies.',
    );
  }

  // 7. Outdated stack across layers.
  const outdated = has(
    findings,
    kb('eol-software', 'known-vulnerable-server', 'vulnerable-dependency', 'vulnerable-js-library'),
  );
  if (outdated.length >= 3) {
    add(
      'INS-008',
      'Outdated components are a recurring theme',
      outdated.some((f) => f.severity === 'critical' || f.severity === 'high') ? 'high' : 'medium',
      `${outdated.length} findings come from components that are out of date or end-of-life. Public exploit code usually appears within days of a disclosure, so lagging versions are the most common way in.`,
      outdated,
      'Turn on automated dependency updates (Dependabot or Renovate), schedule regular patch windows, and add npm audit / pip-audit / OSV-Scanner to CI.',
    );
  }

  // 8. Missing baseline hardening: one config block fixes many.
  const headers = has(
    findings,
    kb(
      'csp-missing',
      'hsts-missing',
      'hsts-weak',
      'xcto-missing',
      'clickjacking',
      'referrer-policy',
      'permissions-policy',
      'info-disclosure-headers',
    ),
  );
  if (headers.length >= 4) {
    add(
      'INS-009',
      'Browser-side hardening is almost entirely missing',
      'medium',
      `${headers.length} separate header findings share one cause: the server sends no security headers. They can all be fixed in a single configuration change (see the fix bundle).`,
      headers,
      'Apply the generated header block for your server or framework, test with the browser console, then tighten the CSP gradually.',
    );
  }

  // 9. Containers and infrastructure that compound.
  const privileged = has(
    findings,
    kb(
      'docker-root',
      'container-privileged',
      'docker-socket',
      'k8s-security-context',
      'k8s-host-namespace',
    ),
  );
  if (privileged.length >= 2) {
    add(
      'INS-010',
      'A compromised container could take over the host',
      privileged.some((f) => f.kb === 'docker-socket' || f.kb === 'container-privileged')
        ? 'high'
        : 'medium',
      'Containers run as root and/or with elevated privileges. An attacker who exploits the application inherits those rights, and with a mounted socket or privileged mode can step out to the host.',
      privileged,
      'Run as a non-root user, drop all capabilities, make the file system read-only, and remove privileged mode and socket mounts.',
    );
  }

  // 10. Weak crypto in more than one place.
  const crypto = has(
    findings,
    kb(
      'weak-hash',
      'weak-cipher',
      'insecure-random',
      'password-storage',
      'jwt-misuse',
      'hardcoded-iv',
      'weak-session-secret',
    ),
  );
  if (crypto.length >= 3) {
    add(
      'INS-011',
      'Cryptography is used inconsistently',
      crypto.some((f) => f.severity === 'high' || f.severity === 'critical') ? 'high' : 'medium',
      'Several places use weak primitives, predictable randomness or hard-coded keys. Individually small, together they suggest no shared, reviewed crypto helper.',
      crypto,
      'Create one small module for hashing, encryption and token generation using vetted libraries, and route all code through it.',
    );
  }
  return out.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
}

const EFFORT_PENALTY: Record<Effort, number> = { minutes: 0, hours: 6, days: 14 };

/** Groups findings that share a remedy and orders the groups: serious and cheap first. */
export function buildFixPlan(findings: readonly Finding[]): FixStep[] {
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    if (f.severity === 'info') continue;
    const key = `${f.kb}${f.facts?.['package'] ? `:${String(f.facts['package'])}` : ''}`;
    const list = groups.get(key) ?? [];
    list.push(f);
    groups.set(key, list);
  }
  const steps = [...groups.entries()].map(([topic, list]) => {
    const maxRisk = Math.max(...list.map((f) => f.risk));
    const effort = TOPICS[topic.split(':')[0] ?? topic]?.effort ?? 'hours';
    const severity =
      list.map((f) => f.severity).sort((a, b) => SEVERITY_RANK[a] - SEVERITY_RANK[b])[0] ?? 'low';
    return {
      topic,
      list,
      effort,
      severity,
      priority: maxRisk + Math.min(12, list.length * 2) - EFFORT_PENALTY[effort],
    };
  });
  steps.sort((a, b) => b.priority - a.priority || effortRank(a.effort) - effortRank(b.effort));
  return steps.map((s, i) => ({
    order: i + 1,
    title: s.list[0]?.advice.summary ?? s.topic,
    why: s.list[0]?.advice.why ?? '',
    effort: s.effort,
    findingIds: s.list.map((f) => f.id),
    severity: s.severity,
  }));
}
