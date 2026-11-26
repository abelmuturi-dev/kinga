import http from 'node:http';
import https from 'node:https';

export interface HttpOptions {
  timeoutMs: number;
  maxBodyBytes: number;
  /** Pause before every request after the first, to stay gentle on the target. */
  delayMs: number;
  /** Hard cap on requests for the whole scan. */
  maxRequests: number;
  userAgent: string;
  /** Skip certificate verification (set automatically after a certificate error is recorded). */
  insecure: boolean;
  sleep: (ms: number) => Promise<void>;
  /** Optional credential header, sent only to this exact origin. */
  auth?: { origin: string; headerName: 'authorization' | 'cookie'; headerValue: string };
}

export interface Hop {
  from: string;
  to: string;
  status: number;
}

export interface Snapshot {
  url: string;
  finalUrl: string;
  status: number;
  /** Header names are lower-cased; repeated headers are kept as separate values. */
  headers: Map<string, string[]>;
  setCookies: string[];
  contentType: string;
  /** Decoded text body, truncated at `maxBodyBytes`; empty for non-text responses. */
  body: string;
  bodyBytes: number;
  bodyTruncated: boolean;
  hops: Hop[];
  durationMs: number;
}

export interface HttpFailure {
  failed: true;
  url: string;
  /** Node error code such as ECONNREFUSED, ENOTFOUND, CERT_HAS_EXPIRED, or `TIMEOUT`. */
  code: string;
  message: string;
  /** True for certificate-chain, expiry and host-name errors. */
  certificate: boolean;
}

export type HttpResult = Snapshot | HttpFailure;

export function isFailure(result: HttpResult): result is HttpFailure {
  return 'failed' in result;
}

export class BudgetExceeded extends Error {
  constructor(limit: number) {
    super(`Request budget of ${limit} reached`);
    this.name = 'BudgetExceeded';
  }
}

const CERT_CODES = new Set([
  'CERT_HAS_EXPIRED',
  'CERT_NOT_YET_VALID',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'UNABLE_TO_GET_ISSUER_CERT',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'CERT_UNTRUSTED',
  'CERT_REVOKED',
  'HOSTNAME_MISMATCH',
]);

const TEXTUAL =
  /^(text\/|application\/(json|xml|javascript|x-javascript|ecmascript|xhtml\+xml|.*\+json|.*\+xml)|image\/svg\+xml)/i;

export interface RequestInit {
  method?: string;
  headers?: Record<string, string>;
  /** Follow redirects (default true, up to 5 hops). Hops are always recorded. */
  follow?: boolean;
  /**
   * Inspect the start of the body whatever its content type, up to this many bytes. Used by exposure
   * probes for files such as `.env`, which servers often label `application/octet-stream`. The body
   * is analysed in memory and never written to a report.
   */
  peekBytes?: number;
}

/**
 * A small, polite HTTP client for scanning. It identifies itself, spaces requests out, enforces a
 * request budget, never sends request bodies, and never decompresses (it asks for identity encoding).
 */
export class HttpClient {
  requests = 0;
  readonly failures: HttpFailure[] = [];

  constructor(private readonly options: HttpOptions) {}

  setInsecure(value: boolean): void {
    this.options.insecure = value;
  }

  get insecure(): boolean {
    return this.options.insecure;
  }

  async request(url: string, init: RequestInit = {}): Promise<HttpResult> {
    const started = Date.now();
    const follow = init.follow !== false;
    const hops: Hop[] = [];
    let current = url;
    for (let i = 0; i <= 5; i++) {
      const once = await this.once(
        current,
        init.method ?? 'GET',
        init.headers ?? {},
        init.peekBytes,
      );
      if (isFailure(once)) {
        this.failures.push(once);
        return once;
      }
      const location = once.headers.get('location')?.[0];
      if (follow && location && once.status >= 300 && once.status < 400 && i < 5) {
        let next: string;
        try {
          next = new URL(location, current).toString();
        } catch {
          return finish(once, url, hops, started);
        }
        if (!isAllowedRedirect(current, next)) {
          // Return the redirect response without following a cross-origin or downgrade hop.
          // This prevents a target from redirecting Kinga to an unrelated/internal service.
          return finish(once, url, hops, started);
        }
        hops.push({ from: current, to: next, status: once.status });
        current = next;
        continue;
      }
      return finish(once, url, hops, started);
    }
    throw new Error('unreachable');
  }

  private async once(
    url: string,
    method: string,
    headers: Record<string, string>,
    peekBytes?: number,
  ): Promise<Snapshot | HttpFailure> {
    if (this.requests >= this.options.maxRequests)
      throw new BudgetExceeded(this.options.maxRequests);
    if (this.requests > 0 && this.options.delayMs > 0)
      await this.options.sleep(this.options.delayMs);
    this.requests++;
    const parsed = new URL(url);
    const lib = parsed.protocol === 'https:' ? https : http;
    const started = Date.now();

    return await new Promise<Snapshot | HttpFailure>((resolve) => {
      let settled = false;
      const done = (value: Snapshot | HttpFailure): void => {
        if (settled) return;
        settled = true;
        resolve(value);
      };
      const fail = (error: NodeJS.ErrnoException): void => {
        const code = error.code ?? (error.name === 'TimeoutError' ? 'TIMEOUT' : 'ERROR');
        done({
          failed: true,
          url,
          code,
          message: error.message,
          certificate: CERT_CODES.has(code),
        });
      };
      const req = lib.request(
        parsed,
        {
          method,
          headers: {
            'user-agent': this.options.userAgent,
            accept: 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5',
            'accept-encoding': 'identity',
            connection: 'close',
            ...headers,
            ...(this.options.auth && parsed.origin === this.options.auth.origin
              ? { [this.options.auth.headerName]: this.options.auth.headerValue }
              : {}),
          },
          rejectUnauthorized: !this.options.insecure,
          timeout: this.options.timeoutMs,
        },
        (res) => {
          const chunks: Buffer[] = [];
          let size = 0;
          let kept = 0;
          let truncated = false;
          const contentType = String(res.headers['content-type'] ?? '');
          const limit = peekBytes ?? this.options.maxBodyBytes;
          const wantBody =
            method !== 'HEAD' &&
            method !== 'OPTIONS' &&
            (peekBytes !== undefined || TEXTUAL.test(contentType));
          res.on('data', (chunk: Buffer) => {
            size += chunk.length;
            if (!wantBody) return;
            if (kept >= limit) {
              truncated = true;
              return;
            }
            const room = limit - kept;
            chunks.push(chunk.length > room ? chunk.subarray(0, room) : chunk);
            kept += Math.min(chunk.length, room);
            if (chunk.length > room) truncated = true;
          });
          res.on('end', () => {
            const headerMap = new Map<string, string[]>();
            for (const [name, value] of Object.entries(res.headers)) {
              if (value === undefined) continue;
              headerMap.set(name.toLowerCase(), Array.isArray(value) ? value : [String(value)]);
            }
            done({
              url,
              finalUrl: url,
              status: res.statusCode ?? 0,
              headers: headerMap,
              setCookies: headerMap.get('set-cookie') ?? [],
              contentType,
              body: wantBody ? Buffer.concat(chunks).toString('utf8') : '',
              bodyBytes: size,
              bodyTruncated: truncated,
              hops: [],
              durationMs: Date.now() - started,
            });
          });
          res.on('error', fail);
        },
      );
      req.on('timeout', () => {
        const error: NodeJS.ErrnoException = new Error(
          `Timed out after ${this.options.timeoutMs} ms`,
        );
        error.code = 'TIMEOUT';
        req.destroy();
        fail(error);
      });
      req.on('error', fail);
      req.end();
    });
  }
}

/**
 * Redirects stay on the original hostname. HTTP->HTTPS upgrades are allowed, but HTTPS
 * downgrades, credential-bearing URLs, non-web schemes and cross-host redirects are not.
 * This is a conservative default for a scanner that may be pointed at untrusted websites.
 */
export function isAllowedRedirect(from: string, to: string): boolean {
  let source: URL;
  let destination: URL;
  try {
    source = new URL(from);
    destination = new URL(to);
  } catch {
    return false;
  }
  if (!['http:', 'https:'].includes(destination.protocol)) return false;
  if (destination.username || destination.password) return false;
  if (source.hostname.toLowerCase() !== destination.hostname.toLowerCase()) return false;
  if (source.protocol === 'https:' && destination.protocol !== 'https:') return false;

  const sourcePort = source.port || (source.protocol === 'https:' ? '443' : '80');
  const destinationPort = destination.port || (destination.protocol === 'https:' ? '443' : '80');
  const standardUpgrade =
    source.protocol === 'http:' &&
    destination.protocol === 'https:' &&
    sourcePort === '80' &&
    destinationPort === '443';
  return sourcePort === destinationPort || standardUpgrade;
}

function finish(last: Snapshot, original: string, hops: Hop[], started: number): Snapshot {
  return { ...last, url: original, finalUrl: last.url, hops, durationMs: Date.now() - started };
}

export function header(snapshot: Snapshot, name: string): string | undefined {
  return snapshot.headers.get(name.toLowerCase())?.[0];
}
