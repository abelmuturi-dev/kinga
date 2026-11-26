import { createServer } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import { HttpClient } from '../src/scanners/web/http.js';

const servers: Array<ReturnType<typeof createServer>> = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => server.close(() => resolve())),
    ),
  );
});

async function listen(server: ReturnType<typeof createServer>): Promise<string> {
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No test server address');
  return `http://127.0.0.1:${address.port}`;
}

function client(auth?: { origin: string; headerName: 'authorization' | 'cookie'; headerValue: string }) {
  return new HttpClient({
    timeoutMs: 2000,
    maxBodyBytes: 1024,
    delayMs: 0,
    maxRequests: 3,
    userAgent: 'Kinga test',
    insecure: false,
    sleep: async () => undefined,
    ...(auth ? { auth } : {}),
  });
}

describe('origin-scoped web authentication', () => {
  it('sends credentials to the explicitly configured origin', async () => {
    let received = '';
    const server = createServer((req, res) => {
      received = String(req.headers.authorization ?? '');
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
    });
    const origin = await listen(server);
    const result = await client({
      origin,
      headerName: 'authorization',
      headerValue: 'Bearer test-token',
    }).request(origin);

    expect('failed' in result).toBe(false);
    expect(received).toBe('Bearer test-token');
  });

  it('does not send credentials to a different origin', async () => {
    let received = '';
    const server = createServer((req, res) => {
      received = String(req.headers.cookie ?? '');
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
    });
    const origin = await listen(server);
    const result = await client({
      origin: 'http://127.0.0.1:1',
      headerName: 'cookie',
      headerValue: 'session=test',
    }).request(origin);

    expect('failed' in result).toBe(false);
    expect(received).toBe('');
  });
});
