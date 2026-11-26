export interface ApiProbeResult {
  method: 'GET';
  path: string;
  url: string;
  status: number | null;
  durationMs: number;
  outcome: 'responded' | 'redirect-blocked' | 'failed';
  note?: string;
}

export interface ApiProbeReport {
  baseOrigin: string;
  operationsConsidered: number;
  requestsSent: number;
  results: ApiProbeResult[];
  issues: Array<{ id: string; severity: 'medium'; path: string; message: string }>;
  notes: string[];
}

export interface ApiProbeOptions {
  authorized: boolean;
  maxOperations?: number;
  timeoutMs?: number;
  auth?: {
    origin: string;
    headerName: 'authorization' | 'cookie';
    headerValue: string;
  };
}

type JsonObject = Record<string, unknown>;

function object(value: unknown): JsonObject | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonObject)
    : null;
}

/**
 * Probes only GET operations from a supplied OpenAPI/Swagger JSON contract.
 * It never sends request bodies, follows redirects or invokes mutating verbs.
 */
export async function probeApiReadOperations(
  document: unknown,
  baseUrlInput: string,
  options: ApiProbeOptions,
): Promise<ApiProbeReport> {
  if (!options.authorized) throw new Error('API probing requires explicit --authorized confirmation.');
  const root = object(document);
  if (!root) throw new Error('API contract must be a JSON object.');
  const openapi = typeof root.openapi === 'string' && /^3\.(0|1)(\.\d+)?$/.test(root.openapi);
  const swagger = root.swagger === '2.0';
  if (!openapi && !swagger) throw new Error('Only OpenAPI 3.x and Swagger 2.0 JSON contracts are supported.');

  let base: URL;
  try {
    base = new URL(baseUrlInput);
  } catch {
    throw new Error('Base URL must be an absolute HTTP(S) URL.');
  }
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash) {
    throw new Error('Base URL must be HTTP(S) without credentials, query or fragment.');
  }
  if (options.auth && options.auth.origin !== base.origin) {
    throw new Error('API credentials must be scoped to the exact base URL origin.');
  }
  const max = options.maxOperations ?? 20;
  if (!Number.isInteger(max) || max < 1 || max > 20) {
    throw new Error('maxOperations must be an integer from 1 to 20.');
  }

  const paths = object(root.paths) ?? {};
  const globalSecurity = Array.isArray(root.security) ? root.security : [];
  const operations: Array<{ path: string; protected: boolean }> = [];
  for (const [pathName, raw] of Object.entries(paths)) {
    const pathItem = object(raw);
    const get = object(pathItem?.get);
    if (!get) continue;
    const security = Array.isArray(get.security) ? get.security : globalSecurity;
    const allowsAnonymous = security.some((entry) => {
      const requirement = object(entry);
      return requirement !== null && Object.keys(requirement).length === 0;
    });
    operations.push({ path: pathName, protected: security.length > 0 && !allowsAnonymous });
    if (operations.length >= max) break;
  }

  const results: ApiProbeResult[] = [];
  const issues: ApiProbeReport['issues'] = [];
  for (const [operationIndex, operation] of operations.entries()) {
    if (operationIndex > 0) await new Promise((resolve) => setTimeout(resolve, 150));
    const path = operation.path.replace(/\{[^}]+\}/g, 'kinga-probe');
    const url = new URL(path.replace(/^\//, ''), base.toString().endsWith('/') ? base : `${base.toString()}/`);
    if (url.origin !== base.origin) {
      results.push({
        method: 'GET',
        path: operation.path,
        url: url.toString(),
        status: null,
        durationMs: 0,
        outcome: 'failed',
        note: 'Operation URL was outside the configured origin and was not requested.',
      });
      continue;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 8000);
    const started = Date.now();
    try {
      const headers: Record<string, string> = { accept: 'application/json', 'user-agent': 'Kinga security scanner' };
      if (options.auth) headers[options.auth.headerName] = options.auth.headerValue;
      const response = await fetch(url, {
        method: 'GET',
        headers,
        redirect: 'manual',
        signal: controller.signal,
      });
      const redirected = response.status >= 300 && response.status < 400;
      await response.body?.cancel();
      results.push({
        method: 'GET',
        path: operation.path,
        url: url.toString(),
        status: response.status,
        durationMs: Date.now() - started,
        outcome: redirected ? 'redirect-blocked' : 'responded',
        ...(redirected ? { note: 'Redirect not followed; credentials were not forwarded.' } : {}),
      });
      if (operation.protected && !options.auth && response.status >= 200 && response.status < 300) {
        issues.push({
          id: 'API-RUNTIME-001',
          severity: 'medium',
          path: operation.path,
          message: 'An operation declared as protected returned a success status without credentials; verify authorization enforcement.',
        });
      }
    } catch (error) {
      results.push({
        method: 'GET',
        path: operation.path,
        url: url.toString(),
        status: null,
        durationMs: Date.now() - started,
        outcome: 'failed',
        note: error instanceof Error ? error.name : 'Request failed',
      });
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    baseOrigin: base.origin,
    operationsConsidered: operations.length,
    requestsSent: results.filter((result) => result.status !== null).length,
    results,
    issues,
    notes: [
      'Only GET operations were requested; no POST, PUT, PATCH, DELETE or request bodies were sent.',
      'Redirects were not followed and requests were limited to the exact configured origin.',
      'A success response on a declared protected route is a review signal, not proof of broken authorization.',
      'Path parameters use the placeholder value "kinga-probe"; endpoints with required query parameters may return errors.',
    ],
  };
}
