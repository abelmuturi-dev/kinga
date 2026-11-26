import { resolve4, resolve6, resolveCname, resolveMx, resolveTxt } from 'node:dns/promises';

export interface DnsPosture {
  domain: string;
  mx: string[];
  spf: string[];
  dmarc: string[];
  dkim: Record<string, string[]>;
  cname: string[];
  subdomainSignals: Array<{ host: string; target: string; targetResolves: boolean; possibleDangling: boolean }>;
  notes: string[];
}

async function safe<T>(fn: () => Promise<T>): Promise<T | []> {
  try { return await fn(); } catch { return []; }
}

function joinTxt(rows: string[][]): string[] {
  return rows.map((parts) => parts.join(''));
}

/** Passive DNS/email posture checks; takeover results are indicators, never proof. */
export async function inspectDns(domain: string): Promise<DnsPosture> {
  const name = domain.trim().toLowerCase().replace(/\.$/, '');
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(name)) {
    throw new Error('Provide a valid fully-qualified domain name.');
  }
  const [mxRows, txtRows, dmarcRows, cnameRows] = await Promise.all([
    safe(() => resolveMx(name)),
    safe(() => resolveTxt(name)),
    safe(() => resolveTxt(`_dmarc.${name}`)),
    safe(() => resolveCname(name)),
  ]);
  const spf = joinTxt(txtRows as string[][]).filter((value) => /^v=spf1\b/i.test(value));
  const dmarc = joinTxt(dmarcRows as string[][]).filter((value) => /^v=DMARC1\b/i.test(value));
  const selectors = ['default', 'google', 'selector1', 'selector2', 'dkim', 'mail'];
  const entries = await Promise.all(selectors.map(async (selector) => {
    const rows = await safe(() => resolveTxt(`${selector}._domainkey.${name}`));
    return [selector, joinTxt(rows as string[][])] as const;
  }));
  const dkim = Object.fromEntries(entries.filter(([, values]) => values.length > 0));
  const mx = (mxRows as Array<{ exchange: string }>).map((row) => row.exchange);
  const cname = cnameRows as string[];

  const labels = ['www', 'api', 'shop', 'blog', 'cdn', 'app', 'mail', 'portal'];
  const subdomainSignals = (await Promise.all(labels.map(async (label) => {
    const host = `${label}.${name}`;
    const rows = await safe(() => resolveCname(host));
    if (!Array.isArray(rows) || rows.length === 0) return null;
    const target = rows[0];
    if (!target) return null;
    const [v4, v6] = await Promise.all([
      safe(() => resolve4(target)),
      safe(() => resolve6(target)),
    ]);
    const targetResolves = (Array.isArray(v4) && v4.length > 0) || (Array.isArray(v6) && v6.length > 0);
    return { host, target, targetResolves, possibleDangling: !targetResolves };
  }))).filter((item): item is NonNullable<typeof item> => item !== null);

  const notes: string[] = [];
  if (!mx.length) notes.push('No MX records were found.');
  if (!spf.length) notes.push('No SPF TXT record was found.');
  if (spf.length > 1) notes.push('Multiple SPF records were found.');
  if (!dmarc.length) notes.push('No DMARC record was found.');
  if (dmarc.some((value) => /\bp=none\b/i.test(value))) notes.push('DMARC policy is monitoring-only (p=none).');
  if (!Object.keys(dkim).length) notes.push('No DKIM record was found for common selectors; other selectors may exist.');
  if (cname.length) notes.push('An apex CNAME exists; assess target ownership manually.');
  if (subdomainSignals.some((item) => item.possibleDangling)) {
    notes.push('A common subdomain has an unresolved CNAME target. This is a takeover signal only, not proof of claimability.');
  }
  return { domain: name, mx, spf, dmarc, dkim, cname, subdomainSignals, notes };
}
