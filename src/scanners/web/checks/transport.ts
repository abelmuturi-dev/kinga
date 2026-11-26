import type { RawFinding } from '../../../core/types.js';
import { webFinding, type WebCheck, type WebContext } from '../context.js';
import { isFailure } from '../http.js';

export const transportChecks: WebCheck = {
  id: 'transport',
  title: 'HTTPS enforcement and redirects',
  level: 'passive',
  run(ctx: WebContext): RawFinding[] {
    const out: RawFinding[] = [];
    const page = ctx.primary;
    const url = ctx.target;

    if (page && page.finalUrl.startsWith('http:')) {
      const loginish = /<input\b[^>]*\btype\s*=\s*["']?password/i.test(page.body);
      out.push(
        webFinding({
          rule: 'WEB-NET-001',
          kb: 'no-https',
          title: 'Site is served over unencrypted HTTP',
          severity: ctx.local ? 'info' : loginish ? 'high' : 'medium',
          confidence: 'high',
          category: 'transport',
          target: page.finalUrl,
          evidence: `The page was delivered over http://${loginish ? ' and contains a password field' : ''}. Anyone on the network path can read or change it.`,
        }),
      );
    }

    if (page) {
      const downgrade = page.hops.find(
        (h) => h.from.startsWith('https:') && h.to.startsWith('http:'),
      );
      if (downgrade) {
        out.push(
          webFinding({
            rule: 'WEB-NET-002',
            kb: 'https-downgrade',
            title: 'Redirect sends visitors from HTTPS back to HTTP',
            severity: 'high',
            confidence: 'high',
            category: 'transport',
            target: downgrade.from,
            evidence: `${downgrade.status} redirect from ${downgrade.from} to ${downgrade.to}.`,
          }),
        );
      }
    }

    const variant = ctx.httpVariant;
    if (variant && !isFailure(variant) && url.protocol === 'https:') {
      const first = variant.hops[0];
      const redirectsToHttps = first !== undefined && first.to.startsWith('https:');
      if (!redirectsToHttps && variant.status >= 200 && variant.status < 400) {
        out.push(
          webFinding({
            rule: 'WEB-NET-003',
            kb: 'http-no-redirect',
            title: 'Plain HTTP is served instead of redirecting to HTTPS',
            severity: ctx.local ? 'info' : 'medium',
            confidence: 'high',
            category: 'transport',
            target: `http://${url.host}/`,
            evidence: `GET http://${url.host}/ answered ${variant.status} without redirecting to HTTPS, so users who type the address without https:// stay unencrypted.`,
          }),
        );
      }
    }
    return out;
  },
};

export const tlsChecks: WebCheck = {
  id: 'tls',
  title: 'TLS certificate and protocol',
  level: 'passive',
  run(ctx: WebContext): RawFinding[] {
    const out: RawFinding[] = [];
    const target = `https://${ctx.target.host}/`;

    if (ctx.certificateError) {
      const { code, message } = ctx.certificateError;
      const expired = code === 'CERT_HAS_EXPIRED';
      const mismatch = code === 'ERR_TLS_CERT_ALTNAME_INVALID';
      const selfSigned = /SELF_SIGNED/.test(code);
      out.push(
        webFinding({
          rule: expired ? 'WEB-TLS-001' : mismatch ? 'WEB-TLS-003' : 'WEB-TLS-002',
          kb: expired ? 'tls-cert-expired' : mismatch ? 'tls-cert-hostname' : 'tls-cert-untrusted',
          title: expired
            ? 'TLS certificate has expired'
            : mismatch
              ? 'TLS certificate does not match the host name'
              : selfSigned
                ? 'TLS certificate is self-signed or not issued by a trusted authority'
                : 'TLS certificate chain cannot be verified',
          severity: ctx.local ? 'info' : 'high',
          confidence: 'high',
          category: 'tls',
          target,
          evidence: `Certificate verification failed (${code}): ${message}`,
        }),
      );
    }

    const tls = ctx.tls;
    if (!tls || tls instanceof Error) {
      if (tls instanceof Error && ctx.target.protocol === 'https:' && !ctx.certificateError) {
        ctx.notes.push(`TLS details unavailable: ${tls.message}`);
      }
      return out;
    }

    if (tls.daysLeft !== null && !ctx.certificateError) {
      if (tls.daysLeft < 0) {
        out.push(
          webFinding({
            rule: 'WEB-TLS-001',
            kb: 'tls-cert-expired',
            title: 'TLS certificate has expired',
            severity: 'high',
            confidence: 'high',
            category: 'tls',
            target,
            evidence: `The certificate expired ${-tls.daysLeft} day(s) ago (${tls.validTo?.toISOString().slice(0, 10)}).`,
          }),
        );
      } else if (tls.daysLeft <= 30) {
        out.push(
          webFinding({
            rule: 'WEB-TLS-004',
            kb: 'tls-cert-expiring',
            title: `TLS certificate expires in ${tls.daysLeft} day(s)`,
            severity: tls.daysLeft <= 7 ? 'high' : tls.daysLeft <= 14 ? 'medium' : 'low',
            confidence: 'high',
            category: 'tls',
            target,
            evidence: `Valid until ${tls.validTo?.toISOString().slice(0, 10)}. Expired certificates cause browser warnings and outages.`,
          }),
        );
      }
    }
    if (tls.keyType === 'rsa' && tls.keyBits !== null && tls.keyBits < 2048) {
      out.push(
        webFinding({
          rule: 'WEB-TLS-005',
          kb: 'tls-weak-key',
          title: `TLS certificate uses a weak ${tls.keyBits}-bit RSA key`,
          severity: 'high',
          confidence: 'high',
          category: 'tls',
          target,
          evidence: `RSA keys shorter than 2048 bits can be factored with modest resources.`,
        }),
      );
    }
    if (tls.signatureWeak) {
      out.push(
        webFinding({
          rule: 'WEB-TLS-006',
          kb: 'tls-weak-signature',
          title: 'TLS certificate is signed with a weak hash (SHA-1 or MD5)',
          severity: 'medium',
          confidence: 'high',
          category: 'tls',
          target,
          evidence: 'Browsers distrust SHA-1 and MD5 certificate signatures.',
        }),
      );
    }
    if (tls.protocol && /^TLSv1(\.1)?$/.test(tls.protocol)) {
      out.push(
        webFinding({
          rule: 'WEB-TLS-007',
          kb: 'tls-legacy-protocol',
          title: `Server negotiated obsolete ${tls.protocol}`,
          severity: 'medium',
          confidence: 'high',
          category: 'tls',
          target,
          evidence: `A modern client was served over ${tls.protocol}.`,
        }),
      );
    }
    for (const legacy of ctx.legacyTls) {
      if (legacy.outcome === 'accepted') {
        out.push(
          webFinding({
            rule: 'WEB-TLS-008',
            kb: 'tls-legacy-protocol',
            title: `Server still accepts ${legacy.version}`,
            severity: 'medium',
            confidence: 'high',
            category: 'tls',
            target,
            evidence: `A handshake limited to ${legacy.version} succeeded. ${legacy.version} was deprecated by RFC 8996 and has known weaknesses.`,
          }),
        );
      } else if (legacy.outcome === 'unknown') {
        ctx.notes.push(
          `${legacy.version} support could not be tested from this machine (its TLS library refuses to attempt it).`,
        );
      }
    }
    if (ctx.tls13 === 'unsupported') {
      out.push(
        webFinding({
          rule: 'WEB-TLS-009',
          kb: 'tls13-unsupported',
          title: 'TLS 1.3 is not supported',
          severity: 'info',
          confidence: 'high',
          category: 'tls',
          target,
          evidence:
            'A TLS 1.3-only handshake was refused. TLS 1.3 is faster and removes legacy cipher suites.',
        }),
      );
    }
    return out;
  },
};
