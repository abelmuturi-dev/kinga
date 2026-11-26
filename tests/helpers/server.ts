import http from 'node:http';
import type { AddressInfo } from 'node:net';

export type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

export async function withServer<T>(
  handler: Handler,
  fn: (base: string) => Promise<T>,
): Promise<T> {
  const server = http.createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  try {
    return await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}
