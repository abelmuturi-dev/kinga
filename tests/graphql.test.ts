import { createServer } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import { auditGraphqlEndpoint } from '../src/assurance/graphql.js';

const servers: Array<ReturnType<typeof createServer>> = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) => new Promise<void>((resolve) => server.close(() => resolve())),
    ),
  );
});

async function serve(handler: Parameters<typeof createServer>[0]): Promise<string> {
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No test server address');
  return `http://127.0.0.1:${address.port}/graphql`;
}

describe('GraphQL endpoint audit', () => {
  it('detects schema introspection with one read-only POST', async () => {
    let requestBody = '';
    const endpoint = await serve((req, res) => {
      req.setEncoding('utf8');
      req.on('data', (chunk) => (requestBody += chunk));
      req.on('end', () => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ data: { __schema: { queryType: { name: 'Query' } } } }));
      });
    });
    const report = await auditGraphqlEndpoint(endpoint, { authorized: true });
    expect(report.introspectionEnabled).toBe(true);
    expect(report.issues[0]?.id).toBe('GRAPHQL-INTROSPECTION-001');
    expect(requestBody).toContain('__schema');
    expect(requestBody.toLowerCase()).not.toContain('mutation');
  });

  it('requires explicit authorization', async () => {
    await expect(
      auditGraphqlEndpoint('http://127.0.0.1:1/graphql', { authorized: false }),
    ).rejects.toThrow(/authorized/);
  });
});
