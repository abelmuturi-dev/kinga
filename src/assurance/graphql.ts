export interface GraphqlIssue {
  id: string;
  severity: 'medium' | 'info';
  message: string;
  recommendation: string;
}

export interface GraphqlAuditReport {
  endpoint: string;
  httpStatus: number;
  introspectionEnabled: boolean;
  issues: GraphqlIssue[];
  notes: string[];
}

export interface GraphqlAuditOptions {
  authorized: boolean;
  timeoutMs?: number;
  auth?: {
    origin: string;
    headerName: 'authorization' | 'cookie';
    headerValue: string;
  };
}

const INTROSPECTION_QUERY =
  'query KingaSchemaExposure { __schema { queryType { name } types { name kind } } }';

/**
 * Sends one read-only GraphQL introspection query. It never sends mutations and
 * never follows redirects. An explicit authorization confirmation is mandatory.
 */
export async function auditGraphqlEndpoint(
  endpointInput: string,
  options: GraphqlAuditOptions,
): Promise<GraphqlAuditReport> {
  if (!options.authorized) {
    throw new Error('GraphQL probing requires explicit --authorized confirmation.');
  }
  let endpoint: URL;
  try {
    endpoint = new URL(endpointInput);
  } catch {
    throw new Error('GraphQL endpoint must be an absolute HTTP(S) URL.');
  }
  if (!['http:', 'https:'].includes(endpoint.protocol) || endpoint.username || endpoint.password) {
    throw new Error('GraphQL endpoint must be HTTP(S) and must not contain URL credentials.');
  }
  if (endpoint.hash) throw new Error('GraphQL endpoint must not contain a URL fragment.');
  if (options.auth && options.auth.origin !== endpoint.origin) {
    throw new Error('GraphQL credentials are only accepted for the exact endpoint origin.');
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 8000);
  try {
    const headers: Record<string, string> = {
      accept: 'application/json',
      'content-type': 'application/json',
      'user-agent': 'Kinga security scanner',
    };
    if (options.auth) {
      headers[options.auth.headerName] = options.auth.headerValue;
    }
    const response = await fetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify({ query: INTROSPECTION_QUERY }),
      redirect: 'manual',
      signal: controller.signal,
    });
    if (response.status >= 300 && response.status < 400) {
      return {
        endpoint: endpoint.toString(),
        httpStatus: response.status,
        introspectionEnabled: false,
        issues: [],
        notes: ['Redirect response was not followed; credentials were not forwarded.'],
      };
    }
    const contentLength = Number(response.headers.get('content-length') ?? 0);
    if (contentLength > 65_536) {
      throw new Error('GraphQL response exceeds the 64 KB safety limit.');
    }
    let body = '';
    if (response.body) {
      const chunks: Uint8Array[] = [];
      let size = 0;
      for await (const chunk of response.body) {
        size += chunk.length;
        if (size > 65_536) {
          controller.abort();
          throw new Error('GraphQL response exceeds the 64 KB safety limit.');
        }
        chunks.push(chunk);
      }
      body = Buffer.concat(chunks).toString('utf8');
    }
    let payload: unknown;
    try {
      payload = JSON.parse(body);
    } catch {
      return {
        endpoint: endpoint.toString(),
        httpStatus: response.status,
        introspectionEnabled: false,
        issues: [],
        notes: ['Endpoint did not return a JSON GraphQL response.'],
      };
    }
    const data =
      payload !== null && typeof payload === 'object'
        ? (payload as { data?: unknown }).data
        : undefined;
    const schema =
      data !== null && typeof data === 'object'
        ? (data as { __schema?: unknown }).__schema
        : undefined;
    const introspectionEnabled = schema !== undefined && schema !== null;
    return {
      endpoint: endpoint.toString(),
      httpStatus: response.status,
      introspectionEnabled,
      issues: introspectionEnabled
        ? [
            {
              id: 'GRAPHQL-INTROSPECTION-001',
              severity: 'info',
              message: 'GraphQL schema introspection is enabled for this endpoint.',
              recommendation:
                'Decide whether schema discovery should be public. If not, restrict introspection in production while preserving authorized developer tooling.',
            },
          ]
        : [],
      notes: [
        'Only one read-only introspection query was sent; no mutations or fuzzing were performed.',
        'Schema exposure is informational and is not, by itself, proof of an exploitable vulnerability.',
      ],
    };
  } finally {
    clearTimeout(timeout);
  }
}
