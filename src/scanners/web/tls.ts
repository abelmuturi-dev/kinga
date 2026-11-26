import { X509Certificate } from 'node:crypto';
import tls from 'node:tls';

export interface TlsInfo {
  host: string;
  port: number;
  protocol: string | null;
  cipher: string | null;
  authorized: boolean;
  authorizationError: string | null;
  subject: string;
  issuer: string;
  validFrom: Date | null;
  validTo: Date | null;
  daysLeft: number | null;
  selfSigned: boolean;
  /** SAN/CN names the certificate covers. */
  names: string[];
  hostMatches: boolean | null;
  keyType: string | null;
  keyBits: number | null;
  signatureWeak: boolean;
}

export interface LegacyProtocolResult {
  version: 'TLSv1' | 'TLSv1.1';
  /** accepted: server completed a handshake. refused: server rejected it. unknown: this machine could not try. */
  outcome: 'accepted' | 'refused' | 'unknown';
}

function hostMatchesName(host: string, name: string): boolean {
  const h = host.toLowerCase();
  const n = name.toLowerCase();
  if (n === h) return true;
  if (n.startsWith('*.')) {
    const suffix = n.slice(1);
    return h.endsWith(suffix) && h.slice(0, h.length - suffix.length).split('.').length === 1;
  }
  return false;
}

export function probeTls(host: string, port: number, timeoutMs: number): Promise<TlsInfo | Error> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value: TlsInfo | Error): void => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const socket = tls.connect(
      {
        host,
        port,
        servername: tlsServerName(host),
        // kinga-ignore-next-line: probing invalid certificates is the purpose of this scanner
        rejectUnauthorized: false,
        timeout: timeoutMs,
      },
      () => {
        try {
          const raw = socket.getPeerX509Certificate();
          const cert = raw ?? null;
          const validFrom = cert ? new Date(cert.validFrom) : null;
          const validTo = cert ? new Date(cert.validTo) : null;
          const names: string[] = [];
          if (cert?.subjectAltName) {
            for (const part of cert.subjectAltName.split(/,\s*/)) {
              const m = /^DNS:(.+)$/.exec(part);
              if (m?.[1]) names.push(m[1]);
            }
          }
          if (names.length === 0 && cert) {
            const cn = /CN=([^\n,]+)/.exec(cert.subject);
            if (cn?.[1]) names.push(cn[1]);
          }
          const key = cert?.publicKey;
          const details = key?.asymmetricKeyDetails;
          const keyType = key?.asymmetricKeyType ?? null;
          const keyBits =
            details?.modulusLength ??
            (keyType === 'ec' && details?.namedCurve
              ? curveBits(details.namedCurve)
              : keyType === 'ed25519'
                ? 256
                : null);
          const text = cert ? safeText(cert) : '';
          finish({
            host,
            port,
            protocol: socket.getProtocol(),
            cipher: socket.getCipher()?.name ?? null,
            authorized: socket.authorized,
            authorizationError: socket.authorizationError
              ? String(socket.authorizationError)
              : null,
            subject: cert?.subject.replace(/\n/g, ', ') ?? '',
            issuer: cert?.issuer.replace(/\n/g, ', ') ?? '',
            validFrom,
            validTo,
            daysLeft: validTo ? Math.floor((validTo.getTime() - Date.now()) / 86_400_000) : null,
            selfSigned: cert ? cert.subject === cert.issuer : false,
            names,
            hostMatches: names.length > 0 ? names.some((n) => hostMatchesName(host, n)) : null,
            keyType,
            keyBits,
            signatureWeak: /Signature Algorithm:\s*(?:md5|sha1)With/i.test(text),
          });
        } catch (error) {
          finish(error instanceof Error ? error : new Error(String(error)));
        } finally {
          socket.end();
        }
      },
    );
    socket.on('timeout', () => {
      socket.destroy();
      finish(new Error(`TLS handshake timed out after ${timeoutMs} ms`));
    });
    socket.on('error', (error) => finish(error));
  });
}

function safeText(cert: X509Certificate): string {
  try {
    return cert.toString();
  } catch {
    return '';
  }
}

function curveBits(curve: string): number | null {
  if (/256|prime256v1/i.test(curve)) return 256;
  if (/384/i.test(curve)) return 384;
  if (/521/i.test(curve)) return 521;
  return null;
}

function tlsServerName(host: string): string | undefined {
  // SNI must not be an IP address.
  return /^[\d.]+$/.test(host) || host.includes(':') ? undefined : host;
}

/**
 * Tries a handshake limited to a legacy protocol version. The result is only "accepted" when the
 * handshake really completed; if this machine's OpenSSL refuses to attempt it, the answer is
 * "unknown" rather than a guess.
 */
export function probeLegacyProtocol(
  host: string,
  port: number,
  version: 'TLSv1' | 'TLSv1.1',
  timeoutMs: number,
): Promise<LegacyProtocolResult> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (outcome: LegacyProtocolResult['outcome']): void => {
      if (settled) return;
      settled = true;
      resolve({ version, outcome });
    };
    let socket: tls.TLSSocket;
    try {
      socket = tls.connect(
        {
          host,
          port,
          servername: tlsServerName(host),
          // kinga-ignore-next-line: probing invalid certificates is the purpose of this scanner
          rejectUnauthorized: false,
          minVersion: version,
          maxVersion: version,
          ciphers: 'ALL:@SECLEVEL=0',
          timeout: timeoutMs,
        },
        () => {
          finish('accepted');
          socket.end();
        },
      );
    } catch {
      finish('unknown');
      return;
    }
    socket.on('timeout', () => {
      socket.destroy();
      finish('unknown');
    });
    socket.on('error', (error: NodeJS.ErrnoException) => {
      const msg = `${error.code ?? ''} ${error.message}`;
      if (
        /NO_PROTOCOLS_AVAILABLE|UNSUPPORTED_PROTOCOL|unsupported protocol|no protocols available/i.test(
          msg,
        )
      ) {
        // Either this client cannot speak the protocol or the server refused it; we cannot tell which.
        finish(/alert|handshake failure|protocol version/i.test(msg) ? 'refused' : 'unknown');
        return;
      }
      if (/ECONNREFUSED|ENOTFOUND|ETIMEDOUT|ECONNRESET/.test(msg)) {
        finish(/ECONNRESET/.test(msg) ? 'refused' : 'unknown');
        return;
      }
      finish(
        /alert|handshake failure|protocol version|wrong version/i.test(msg) ? 'refused' : 'unknown',
      );
    });
  });
}

/** Whether the server completes a handshake restricted to TLS 1.3. */
export function probeTls13(
  host: string,
  port: number,
  timeoutMs: number,
): Promise<'supported' | 'unsupported' | 'unknown'> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v: 'supported' | 'unsupported' | 'unknown'): void => {
      if (done) return;
      done = true;
      resolve(v);
    };
    const socket = tls.connect(
      {
        host,
        port,
        servername: tlsServerName(host),
        // kinga-ignore-next-line: probing invalid certificates is the purpose of this scanner
        rejectUnauthorized: false,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        timeout: timeoutMs,
      },
      () => {
        finish('supported');
        socket.end();
      },
    );
    socket.on('timeout', () => {
      socket.destroy();
      finish('unknown');
    });
    socket.on('error', (error: NodeJS.ErrnoException) => {
      const msg = `${error.code ?? ''} ${error.message}`;
      finish(
        /alert|handshake failure|protocol version|wrong version/i.test(msg)
          ? 'unsupported'
          : 'unknown',
      );
    });
  });
}
