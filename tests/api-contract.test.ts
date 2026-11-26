import { describe, expect, it } from 'vitest';
import { auditApiContract } from '../src/assurance/api-contract.js';

describe('OpenAPI contract audit', () => {
  it('flags public write operations and cleartext production servers', () => {
    const report = auditApiContract({
      openapi: '3.1.0',
      servers: [{ url: 'http://api.example.test/v1' }],
      paths: {
        '/users': {
          post: {
            operationId: 'createUser',
            responses: { '201': { description: 'created' } },
          },
        },
      },
    });

    expect(report.operations).toBe(1);
    expect(report.publicOperations).toBe(1);
    expect(report.issues.map((issue) => issue.id)).toEqual(
      expect.arrayContaining(['API-SERVER-003', 'API-AUTH-001', 'API-AUTH-002']),
    );
  });

  it('inherits global security and accepts local HTTP servers', () => {
    const report = auditApiContract({
      openapi: '3.0.3',
      servers: [{ url: 'http://localhost:8080' }],
      components: {
        securitySchemes: {
          bearerAuth: { type: 'http', scheme: 'bearer' },
        },
      },
      security: [{ bearerAuth: [] }],
      paths: {
        '/health': {
          get: {
            operationId: 'health',
            responses: { '200': { description: 'ok' } },
          },
        },
      },
    });

    expect(report.securedOperations).toBe(1);
    expect(report.publicOperations).toBe(0);
    expect(report.issues.some((issue) => issue.id === 'API-SERVER-003')).toBe(false);
  });

  it('honours an explicitly public operation and reports missing security schemes', () => {
    const report = auditApiContract({
      swagger: '2.0',
      schemes: ['https'],
      securityDefinitions: {
        key: { type: 'apiKey', name: 'key', in: 'header' },
      },
      security: [{ key: [] }],
      paths: {
        '/public': {
          get: { operationId: 'readPublic', security: [], responses: {} },
        },
        '/private': {
          post: {
            operationId: 'writePrivate',
            security: [{ missing: [] }],
            responses: {},
          },
        },
      },
    });

    expect(report.publicOperations).toBe(1);
    expect(report.issues.some((issue) => issue.id === 'API-AUTH-003')).toBe(true);
    expect(report.issues.some((issue) => issue.id === 'API-AUTH-004')).toBe(true);
  });

  it('detects anonymous alternatives in security requirements', () => {
    const report = auditApiContract({
      openapi: '3.1.0',
      servers: [{ url: '/v1' }],
      components: {
        securitySchemes: {
          bearerAuth: { type: 'http', scheme: 'bearer' },
        },
      },
      paths: {
        '/write': {
          post: {
            operationId: 'write',
            security: [{ bearerAuth: [] }, { missing: [] }, {}],
            responses: {},
          },
        },
      },
    });

    expect(report.publicOperations).toBe(1);
    expect(
      report.issues.some((issue) =>
        issue.message.includes('anonymous-access alternative'),
      ),
    ).toBe(true);
    expect(report.issues.some((issue) => issue.id === 'API-AUTH-004')).toBe(true);
    expect(report.issues.some((issue) => issue.id === 'API-SERVER-005')).toBe(false);
  });

  it('warns about query-string API keys and Basic authentication', () => {
    const report = auditApiContract({
      openapi: '3.0.3',
      servers: [{ url: 'https://api.example.test' }],
      components: {
        securitySchemes: {
          queryKey: { type: 'apiKey', name: 'key', in: 'query' },
          basicAuth: { type: 'http', scheme: 'basic' },
        },
      },
      paths: {},
    });

    expect(report.issues.map((issue) => issue.id)).toEqual(
      expect.arrayContaining(['API-AUTH-005', 'API-AUTH-006']),
    );
  });

  it('treats omitted OpenAPI servers as the specification default', () => {
    const report = auditApiContract({
      openapi: '3.1.0',
      components: {
        securitySchemes: {
          bearerAuth: { type: 'http', scheme: 'bearer' },
        },
      },
      security: [{ bearerAuth: [] }],
      paths: {
        '/health': {
          get: { operationId: 'health', responses: {} },
        },
      },
    });

    expect(report.issues.some((issue) => issue.id === 'API-SERVER-001')).toBe(true);
    expect(report.issues.find((issue) => issue.id === 'API-SERVER-001')?.severity).toBe(
      'info',
    );
  });

  it('rejects unsupported and malformed documents', () => {
    expect(() => auditApiContract([])).toThrow(/JSON object/);
    expect(() => auditApiContract({ openapi: '2.0', paths: {} })).toThrow(/Only OpenAPI/);
  });
});
