export type ApiIssueSeverity = 'high' | 'medium' | 'low' | 'info';

export interface ApiContractIssue {
  id: string;
  severity: ApiIssueSeverity;
  location: string;
  message: string;
  recommendation: string;
}

export interface ApiContractReport {
  format: 'openapi' | 'swagger';
  version: string;
  operations: number;
  securedOperations: number;
  publicOperations: number;
  issues: ApiContractIssue[];
}

type JsonObject = Record<string, unknown>;

const METHODS = [
  'get',
  'put',
  'post',
  'delete',
  'options',
  'head',
  'patch',
  'trace',
] as const;

function object(value: unknown): JsonObject | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonObject)
    : null;
}

function strings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string')
    : [];
}

function isLocalServer(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  return (
    host === 'localhost' ||
    host === '::1' ||
    host === '127.0.0.1' ||
    host.endsWith('.localhost') ||
    /^127\./.test(host)
  );
}

function add(
  issues: ApiContractIssue[],
  id: string,
  severity: ApiIssueSeverity,
  location: string,
  message: string,
  recommendation: string,
): void {
  issues.push({ id, severity, location, message, recommendation });
}

/**
 * Audit an already-parsed OpenAPI 3.x or Swagger 2.0 document.
 * This is static analysis only: it makes no network requests and never calls API operations.
 */
export function auditApiContract(document: unknown): ApiContractReport {
  const root = object(document);
  if (!root) throw new Error('API contract must be a JSON object.');

  const openapi = typeof root.openapi === 'string' ? root.openapi : '';
  const swagger = typeof root.swagger === 'string' ? root.swagger : '';
  const isOpenApi = /^3\.(0|1)(\.\d+)?$/.test(openapi);
  const isSwagger = swagger === '2.0';

  if (!isOpenApi && !isSwagger) {
    throw new Error('Only OpenAPI 3.0/3.1 and Swagger 2.0 JSON documents are supported.');
  }

  const issues: ApiContractIssue[] = [];
  const paths = object(root.paths) ?? {};
  const components = object(root.components);
  const schemes = object(isOpenApi ? components?.securitySchemes : root.securityDefinitions) ?? {};
  const globalSecurity = Array.isArray(root.security) ? root.security : undefined;
  const seenOperationIds = new Set<string>();
  let operations = 0;
  let securedOperations = 0;
  let publicOperations = 0;

  if (isOpenApi) {
    const servers = Array.isArray(root.servers) ? root.servers : [];
    if (servers.length === 0) {
      add(
        issues,
        'API-SERVER-001',
        'medium',
        'servers',
        'No server URL is declared.',
        'Declare the intended API base URL and keep environment-specific URLs outside production contracts.',
      );
    }

    servers.forEach((entry, index) => {
      const server = object(entry);
      const raw = typeof server?.url === 'string' ? server.url : '';
      if (!raw) {
        add(
          issues,
          'API-SERVER-002',
          'medium',
          `servers[${index}]`,
          'Server entry has no URL.',
          'Provide a valid absolute server URL.',
        );
        return;
      }

      const candidate = raw.replace(/\{([^}]+)\}/g, (_match, name: string) => {
        const variables = object(server?.variables);
        const variable = object(variables?.[name]);
        return typeof variable?.default === 'string' ? variable.default : 'placeholder';
      });

      if (!/^[a-z][a-z0-9+.-]*:/i.test(candidate)) return;

      try {
        const url = new URL(candidate);
        if (url.username || url.password) {
          add(
            issues,
            'API-SERVER-008',
            'high',
            `servers[${index}]`,
            'API server URL contains embedded credentials.',
            'Remove credentials from server URLs and use the documented authentication mechanism instead.',
          );
        }
        if (url.protocol === 'http:' && !isLocalServer(url.hostname)) {
          add(
            issues,
            'API-SERVER-003',
            'high',
            `servers[${index}]`,
            'API server uses cleartext HTTP.',
            'Use HTTPS for non-local API environments to protect credentials and request data in transit.',
          );
        } else if (!['http:', 'https:'].includes(url.protocol)) {
          add(
            issues,
            'API-SERVER-004',
            'medium',
            `servers[${index}]`,
            'API server uses an unsupported URL scheme.',
            'Use an HTTPS URL, or HTTP only for an explicitly local development server.',
          );
        }
      } catch {
        add(
          issues,
          'API-SERVER-005',
          'medium',
          `servers[${index}]`,
          'API server URL is not a valid absolute URL.',
          'Use a valid absolute URL and define defaults for all server variables.',
        );
      }
    });
  } else {
    const declaredSchemes = strings(root.schemes);
    if (declaredSchemes.includes('http') && !declaredSchemes.includes('https')) {
      add(
        issues,
        'API-SERVER-003',
        'high',
        'schemes',
        'Swagger contract advertises only cleartext HTTP.',
        'Advertise HTTPS for non-local API environments.',
      );
    } else if (declaredSchemes.includes('http') && declaredSchemes.includes('https')) {
      add(
        issues,
        'API-SERVER-006',
        'medium',
        'schemes',
        'Swagger contract permits cleartext HTTP as well as HTTPS.',
        'Remove HTTP from production schemes; keep insecure transport limited to local development.',
      );
    }
  }

  if (Object.keys(schemes).length === 0) {
    add(
      issues,
      'API-AUTH-001',
      'medium',
      isOpenApi ? 'components.securitySchemes' : 'securityDefinitions',
      'No authentication schemes are declared.',
      'Declare the authentication mechanisms used by the API and apply them globally or per operation where appropriate.',
    );
  }

  for (const [name, rawScheme] of Object.entries(schemes)) {
    const scheme = object(rawScheme);
    if (scheme?.type === 'apiKey' && scheme.in === 'query') {
      add(
        issues,
        'API-AUTH-005',
        'medium',
        `securitySchemes.${name}`,
        'API key is configured in the query string.',
        'Prefer an authorization header; query strings are commonly copied into logs, browser history and monitoring systems.',
      );
    }
    if (scheme?.type === 'http' && scheme.scheme === 'basic') {
      add(
        issues,
        'API-AUTH-006',
        'medium',
        `securitySchemes.${name}`,
        'HTTP Basic authentication is declared.',
        'Prefer short-lived bearer tokens or another modern authentication mechanism, and require HTTPS everywhere.',
      );
    }
  }

  for (const [pathName, rawPathItem] of Object.entries(paths)) {
    const pathItem = object(rawPathItem);
    if (!pathItem) continue;

    for (const method of METHODS) {
      const operation = object(pathItem[method]);
      if (!operation) continue;

      operations++;
      const location = `${method.toUpperCase()} ${pathName}`;
      const operationId =
        typeof operation.operationId === 'string' ? operation.operationId.trim() : '';

      if (!operationId) {
        add(
          issues,
          'API-DOC-001',
          'low',
          location,
          'Operation has no operationId.',
          'Add a unique, stable operationId to improve client generation and API traceability.',
        );
      } else if (seenOperationIds.has(operationId)) {
        add(
          issues,
          'API-DOC-002',
          'medium',
          location,
          `Duplicate operationId "${operationId}".`,
          'Give every operation a unique operationId.',
        );
      } else {
        seenOperationIds.add(operationId);
      }

      const effectiveSecurity = Array.isArray(operation.security)
        ? operation.security
        : globalSecurity;

      const allowsAnonymous = effectiveSecurity?.some((requirement) => {
        const requirementObject = object(requirement);
        return requirementObject !== null && Object.keys(requirementObject).length === 0;
      }) ?? false;

      if (!effectiveSecurity || effectiveSecurity.length === 0 || allowsAnonymous) {
        publicOperations++;
        const mutating = ['put', 'post', 'patch', 'delete'].includes(method);
        add(
          issues,
          mutating ? 'API-AUTH-002' : 'API-AUTH-003',
          mutating ? 'high' : 'medium',
          location,
          allowsAnonymous
            ? 'Security requirements include an anonymous-access alternative.'
            : mutating
              ? 'State-changing operation is explicitly or implicitly public.'
              : 'Operation has no declared authentication requirement.',
          'If the operation is intended to be public, document that decision and enforce authorization rules server-side. Otherwise attach an appropriate security requirement.',
        );
      } else {
        securedOperations++;
        for (const requirement of effectiveSecurity) {
          const requirementObject = object(requirement);
          if (!requirementObject) continue;
          for (const schemeName of Object.keys(requirementObject)) {
            if (!(schemeName in schemes)) {
              add(
                issues,
                'API-AUTH-004',
                'high',
                location,
                `Security requirement references undefined scheme "${schemeName}".`,
                'Define the referenced security scheme or correct the requirement name.',
              );
            }
          }
        }
      }
    }
  }

  if (operations === 0) {
    add(
      issues,
      'API-DOC-003',
      'medium',
      'paths',
      'No API operations were found.',
      'Check that the contract contains a populated paths object.',
    );
  }

  return {
    format: isOpenApi ? 'openapi' : 'swagger',
    version: isOpenApi ? openapi : swagger,
    operations,
    securedOperations,
    publicOperations,
    issues,
  };
}
