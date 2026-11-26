import { randomBytes } from 'node:crypto';
import { BRAND } from '../../brand.js';
import { UserError } from '../../errors.js';
import type { RawFinding, TargetSummary } from '../../core/types.js';
import { BUILTIN_WEB_CHECKS } from './checks/index.js';
import { isHtml, isLocalHost, type WebCheck, type WebContext, type WebLevel } from './context.js';
import { findTags, resolveUrl } from './html.js';
import { BudgetExceeded, HttpClient, isFailure, type HttpResult, type Snapshot } from './http.js';
import { probeLegacyProtocol, probeTls, probeTls13 } from './tls.js';

export interface WebScanOptions {
  level: WebLevel;
  /** Confirms the person scanning owns the target or has written permission (needed for active scans of non-local hosts). */
  authorized: boolean;
  timeoutMs: number;
  delayMs: number;
  maxRequests: number;
  maxPages: number;
  /** Continue even if the certificate is invalid (always recorded as a finding). */
  insecure: boolean;
  version: string;
  sleep: (ms: number) => Promise<void>;
  now?: Date;
  /** Optional credentials, sent only to the explicitly configured origin. */
  auth?: { origin: string; headerName: 'authorization' | 'cookie'; headerValue: string };
  /** Extra checks from plugins. */
  extraChecks?: readonly WebCheck[];
}

export const DEFAULT_WEB_OPTIONS: Omit<WebScanOptions, 'version' | 'sleep'> = {
  level: 'passive',
  authorized: false,
  timeoutMs: 10_000,
  delayMs: 250,
  maxRequests: 80,
  maxPages: 10,
  insecure: false,
};

export interface WebScanOutput {
  findings: RawFinding[];
  summary: Extract<TargetSummary, { kind: 'web' }>;
  context: WebContext;
}

/** Turns what a person typed into a URL. A bare host gets https:// (or http:// for local addresses). */
export function normalizeTarget(input: string): URL {
  const trimmed = input.trim();
  if (trimmed === '') throw new UserError('Empty web target.');
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed);
  let url: URL;
  try {
    const guess = hasScheme
      ? trimmed
      : `${isLocalHost(trimmed.split(/[/:?#]/)[0] ?? '') ? 'http' : 'https'}://${trimmed}`;
    url = new URL(guess);
  } catch {
    throw new UserError(`"${input}" is not a valid URL.`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:')
    throw new UserError(`Only http:// and https:// targets can be scanned (got ${url.protocol}).`);
  if (url.username || url.password)
    throw new UserError('Targets with credentials in the URL are not supported.');
  url.hash = '';
  return url;
}

const SKIP_LINK =
  /(log-?out|sign-?out|delete|remove|destroy|unsubscribe|reset|checkout|\.(png|jpe?g|gif|svg|ico|css|js|map|pdf|zip|gz|mp4|mp3|woff2?|ttf|eot|webp)(\?|$))/i;

function extractLinks(page: Snapshot, origin: string): string[] {
  const out = new Set<string>();
  for (const a of findTags(page.body, 'a')) {
    const href = a.attrs['href'];
    if (!href) continue;
    const u = resolveUrl(href, page.finalUrl);
    if (!u || u.origin !== origin || SKIP_LINK.test(u.pathname + u.search)) continue;
    u.hash = '';
    out.add(u.toString());
  }
  return [...out];
}

export async function runWebScan(
  targetInput: string,
  options: WebScanOptions,
): Promise<WebScanOutput> {
  const target = normalizeTarget(targetInput);
  const local = isLocalHost(target.hostname);
  if (options.auth && !options.authorized && !local) {
    throw new UserError('Authenticated scanning requires --authorized for non-local targets.');
  }
  if (options.auth && options.auth.origin !== target.origin) {
    throw new UserError('KINGA_AUTH_ORIGIN must exactly match the scanned target origin.');
  }
  if (options.level === 'active' && !local && !options.authorized) {
    throw new UserError(
      `Active scanning sends extra probe requests, so it needs your confirmation that you own ${target.host} or have written permission to test it.\n` +
        `Re-run with --authorized to confirm, or use the default passive level.`,
    );
  }

  const client = new HttpClient({
    timeoutMs: options.timeoutMs,
    maxBodyBytes: 1_500_000,
    delayMs: options.delayMs,
    maxRequests: options.maxRequests,
    userAgent: BRAND.userAgent(options.version),
    insecure: options.insecure,
    sleep: options.sleep,
    ...(options.auth ? { auth: options.auth } : {}),
  });
  const ctx: WebContext = {
    target,
    level: options.level,
    local,
    client,
    primary: null,
    pages: [],
    httpVariant: null,
    tls: null,
    legacyTls: [],
    tls13: null,
    wellKnown: new Map(),
    notFoundProbe: null,
    certificateError: null,
    notes: [],
    now: options.now ?? new Date(),
  };

  try {
    await collect(ctx, options);
  } catch (error) {
    if (error instanceof BudgetExceeded)
      ctx.notes.push(`${error.message}; the scan stopped early.`);
    else throw error;
  }

  const findings: RawFinding[] = [];
  const checks = [...BUILTIN_WEB_CHECKS, ...(options.extraChecks ?? [])].filter(
    (c) => c.level === 'passive' || options.level === 'active',
  );
  for (const check of checks) {
    try {
      findings.push(...(await check.run(ctx)));
    } catch (error) {
      if (error instanceof BudgetExceeded) {
        ctx.notes.push(`${check.title}: ${error.message}.`);
        continue;
      }
      ctx.notes.push(
        `Check "${check.id}" failed and was skipped: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  if (!ctx.primary) {
    const failure = client.failures[0];
    findings.push({
      rule: 'WEB-NET-000',
      kb: 'unreachable',
      title: 'Target could not be reached',
      severity: 'info',
      confidence: 'high',
      domain: 'web',
      category: 'availability',
      target: target.toString(),
      evidence: failure ? `${failure.code}: ${failure.message}` : 'No response was received.',
      verified: true,
      verification: 'The connection attempt failed; nothing else could be assessed.',
    });
  }

  return {
    findings,
    context: ctx,
    summary: {
      kind: 'web',
      url: target.toString(),
      level: options.level,
      requests: client.requests,
      pagesAnalysed: ctx.pages.length,
      reachable: ctx.primary !== null,
      notes: ctx.notes,
    },
  };
}

async function collect(ctx: WebContext, options: WebScanOptions): Promise<void> {
  const { target, client } = ctx;

  // 1. TLS handshake details (independent of the HTTP request).
  if (target.protocol === 'https:') {
    const port = Number(target.port || 443);
    ctx.tls = await probeTls(target.hostname, port, options.timeoutMs);
    if (options.level === 'active') {
      ctx.legacyTls = [
        await probeLegacyProtocol(target.hostname, port, 'TLSv1', options.timeoutMs),
        await probeLegacyProtocol(target.hostname, port, 'TLSv1.1', options.timeoutMs),
      ];
    }
  }

  // 2. The main page. If the certificate is rejected, record it and carry on without verification.
  let first: HttpResult = await client.request(target.toString());
  if (isFailure(first) && first.certificate) {
    ctx.certificateError = { code: first.code, message: first.message };
    client.setInsecure(true);
    first = await client.request(target.toString());
  }
  if (isFailure(first)) return;
  ctx.primary = first;
  if (isHtml(first) || first.body !== '') ctx.pages.push(first);

  // 3. Does plain HTTP redirect to HTTPS?
  if (target.protocol === 'https:' && (target.port === '' || target.port === '443')) {
    ctx.httpVariant = await client.request(`http://${target.hostname}/`, { follow: true });
  }

  // 4. Well-known files that any site is expected to serve.
  for (const path of ['/robots.txt', '/.well-known/security.txt']) {
    ctx.wellKnown.set(path, await client.request(`${target.origin}${path}`, { follow: false }));
  }

  if (options.level !== 'active') return;

  // 5. Active only: a path that should not exist, then a small same-origin crawl.
  const probe = await client.request(
    `${target.origin}/kinga-${randomBytes(5).toString('hex')}-404`,
    {
      follow: false,
    },
  );
  if (!isFailure(probe)) ctx.notFoundProbe = probe;

  if (target.protocol === 'https:') {
    ctx.tls13 = await probeTls13(target.hostname, Number(target.port || 443), options.timeoutMs);
  }

  const seen = new Set<string>([first.finalUrl]);
  const queue = extractLinks(first, target.origin);
  while (queue.length > 0 && ctx.pages.length < options.maxPages) {
    const next = queue.shift();
    if (next === undefined || seen.has(next)) continue;
    seen.add(next);
    const res = await client.request(next, { follow: true });
    if (isFailure(res)) continue;
    if (new URL(res.finalUrl).origin !== target.origin) continue;
    // Server errors are kept: they are where stack traces and debug output show up.
    if (res.status >= 500 && res.body !== '') {
      ctx.pages.push(res);
      continue;
    }
    if (res.status >= 400) continue;
    if (!isHtml(res)) continue;
    ctx.pages.push(res);
    for (const link of extractLinks(res, target.origin)) if (!seen.has(link)) queue.push(link);
  }
}
