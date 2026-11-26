import type { RawFinding } from '../../core/types.js';
import type { HttpClient, HttpResult, Snapshot } from './http.js';
import type { LegacyProtocolResult, TlsInfo } from './tls.js';

export type WebLevel = 'passive' | 'active';

/** Everything the collection phase learned, handed to each web check. */
export interface WebContext {
  /** Normalised scan target. */
  target: URL;
  level: WebLevel;
  /** True when the target is loopback or a private-network address (typical for dev servers). */
  local: boolean;
  client: HttpClient;
  /** The main page after redirects, or null if the target could not be fetched. */
  primary: Snapshot | null;
  /** Every HTML-ish page fetched (the primary page first). */
  pages: Snapshot[];
  /** Result of requesting the plain-http variant of an https target (null when not applicable). */
  httpVariant: HttpResult | null;
  tls: TlsInfo | Error | null;
  legacyTls: LegacyProtocolResult[];
  tls13: 'supported' | 'unsupported' | 'unknown' | null;
  /** Fixed-path resources requested during collection, keyed by path (e.g. `/robots.txt`). */
  wellKnown: Map<string, HttpResult>;
  /** Response to a request for a path that should not exist (soft-404 and error-page analysis). */
  notFoundProbe: Snapshot | null;
  /** Certificate error seen when the first request was made with verification on. */
  certificateError: { code: string; message: string } | null;
  notes: string[];
  now: Date;
}

export interface WebCheck {
  id: string;
  title: string;
  level: WebLevel;
  run(ctx: WebContext): Promise<RawFinding[]> | RawFinding[];
}

type FindingInit = Omit<RawFinding, 'domain' | 'verified' | 'verification' | 'category'> &
  Partial<Pick<RawFinding, 'verified' | 'verification' | 'category'>>;

/** Builds a web finding with sensible defaults (observed facts are verified). */
export function webFinding(init: FindingInit): RawFinding {
  return {
    domain: 'web',
    category: 'misconfiguration',
    verified: true,
    verification: 'Observed directly in the live HTTP response.',
    ...init,
  };
}

export function isLocalHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h.endsWith('.localhost') || h === '::1') return true;
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(h);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return (
    a === 127 ||
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254)
  );
}

export function isHtml(snapshot: Snapshot): boolean {
  return /html|xml/i.test(snapshot.contentType) || /^\s*<(!doctype|html)/i.test(snapshot.body);
}
