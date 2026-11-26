import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import { probeApiReadOperations } from '../src/assurance/api-probe.js';

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

const servers: Array<ReturnType<typeof createServer>> = [];

afterEach(async () => {
  await Promise.all(
    servers
      .splice(0)
      .map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
  );
});

async function listen(handler: Handler): Promise<string> {
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No server address');
  return `http://127.0.0.1:${address.port}`;
}

describe('authorized API read-only probing', () => {
  it('probes only GET operations and flags declared protected routes returning 2xx anonymously', async () => {
    const methods: string[] = [];
    const base = await listen((req, res) => {
      methods.push(req.method ?? '');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
    });
    const report = await probeApiReadOperations(
      {
        openapi: '3.0.3',
        paths: {
          '/users': { get: { security: [{ bearer: [] }] }, post: {} },
          '/health': { get: { security: [] } },
        },
      },
      base,
      { authorized: true },
    );
    expect(methods).toEqual(['GET', 'GET']);
    expect(report.issues).toHaveLength(1);
    expect(report.issues[0]?.id).toBe('API-RUNTIME-001');
  });

  it('refuses credentials over remote cleartext HTTP', async () => {
    await expect(
      probeApiReadOperations({ openapi: '3.0.3', paths: {} }, 'http://api.example.test', {
        authorized: true,
        auth: {
          origin: 'http://api.example.test',
          headerName: 'authorization',
          headerValue: 'Bearer test',
        },
      }),
    ).rejects.toThrow(/HTTPS/);
  });

  it('refuses to probe without explicit authorization', async () => {
    await expect(
      probeApiReadOperations({ openapi: '3.0.3', paths: {} }, 'http://127.0.0.1', {
        authorized: false,
      }),
    ).rejects.toThrow(/authorized/);
  });
});
