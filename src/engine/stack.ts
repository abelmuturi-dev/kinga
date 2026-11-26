import type { StackInfo, StackKey } from '../core/types.js';
import type { RepoIndex } from '../repo/index.js';
import { header } from '../scanners/web/http.js';
import type { WebContext } from '../scanners/web/context.js';

type Detected = StackInfo['detected'][number];

/** Technology families: a fix example written for `key` also suits every stack listed under it. */
export const FAMILY: Record<string, StackKey[]> = {
  node: ['node', 'express', 'nextjs'],
  python: ['python', 'django', 'flask', 'fastapi'],
  java: ['java', 'spring'],
  php: ['php', 'laravel', 'wordpress'],
  ruby: ['ruby', 'rails'],
  dotnet: ['dotnet', 'iis'],
};

/** Stacks a given detected stack can use examples from (itself plus its parent language). */
export function compatibleKeys(detected: readonly StackKey[]): Set<StackKey> {
  const out = new Set<StackKey>(detected);
  for (const key of detected) {
    for (const [parent, members] of Object.entries(FAMILY)) {
      if (members.includes(key)) out.add(parent as StackKey);
    }
  }
  return out;
}

const COOKIE_HINTS: Array<[RegExp, StackKey, string]> = [
  [/^PHPSESSID$/i, 'php', 'PHPSESSID cookie'],
  [/^JSESSIONID$/i, 'java', 'JSESSIONID cookie'],
  [/^(csrftoken|sessionid)$/i, 'django', 'csrftoken/sessionid cookie'],
  [/^connect\.sid$/i, 'express', 'connect.sid cookie'],
  [/^laravel_session$/i, 'laravel', 'laravel_session cookie'],
  [/^ASP\.NET_SessionId$|^\.AspNetCore\./i, 'dotnet', 'ASP.NET cookie'],
  [/^_session_id$|^_\w+_session$/i, 'rails', 'Rails-style session cookie'],
];

export function detectWebStack(ctx: WebContext): Detected[] {
  const out: Detected[] = [];
  const add = (stack: StackKey, label: string, evidence: string): void => {
    if (!out.some((d) => d.stack === stack)) out.push({ stack, label, evidence });
  };
  const page = ctx.primary;
  if (!page) return out;
  const server = header(page, 'server') ?? '';
  const powered = header(page, 'x-powered-by') ?? '';
  if (/nginx/i.test(server)) add('nginx', 'nginx', `Server: ${server}`);
  if (/apache/i.test(server)) add('apache', 'Apache', `Server: ${server}`);
  if (/caddy/i.test(server)) add('caddy', 'Caddy', `Server: ${server}`);
  if (/iis/i.test(server)) add('iis', 'IIS', `Server: ${server}`);
  if (/express/i.test(powered)) add('express', 'Express', `X-Powered-By: ${powered}`);
  if (/next\.js/i.test(powered)) add('nextjs', 'Next.js', `X-Powered-By: ${powered}`);
  if (/php/i.test(powered)) add('php', 'PHP', `X-Powered-By: ${powered}`);
  if (/asp\.net/i.test(powered) || header(page, 'x-aspnet-version'))
    add('dotnet', 'ASP.NET', 'ASP.NET headers');
  if (/werkzeug/i.test(server)) add('flask', 'Flask', `Server: ${server}`);
  if (/gunicorn|uvicorn|wsgiserver/i.test(server)) add('python', 'Python', `Server: ${server}`);
  if (/jetty|tomcat|coyote/i.test(server)) add('java', 'Java', `Server: ${server}`);
  for (const p of ctx.pages) {
    for (const raw of p.setCookies) {
      const name = raw.split('=')[0]?.trim() ?? '';
      for (const [re, stack, label] of COOKIE_HINTS) if (re.test(name)) add(stack, stack, label);
    }
    if (/\/wp-(content|includes)\//.test(p.body))
      add('wordpress', 'WordPress', 'wp-content paths in HTML');
    if (/\/_next\/static\//.test(p.body)) add('nextjs', 'Next.js', '/_next/static assets');
    if (/<meta[^>]+generator[^>]+wordpress/i.test(p.body))
      add('wordpress', 'WordPress', 'generator meta tag');
  }
  return out;
}

export function detectProjectStack(index: RepoIndex): Detected[] {
  const out: Detected[] = [];
  const add = (stack: StackKey, label: string, evidence: string): void => {
    if (!out.some((d) => d.stack === stack)) out.push({ stack, label, evidence });
  };
  const { profile, inventory } = index;
  const frameworks = profile.frameworks.map((f) => f.toLowerCase());
  const has = (s: string): boolean => frameworks.some((f) => f.includes(s));
  if (has('next')) add('nextjs', 'Next.js', 'framework detected in manifest');
  if (has('express')) add('express', 'Express', 'framework detected in manifest');
  if (has('django')) add('django', 'Django', 'framework detected in manifest');
  if (has('flask')) add('flask', 'Flask', 'framework detected in manifest');
  if (has('fastapi')) add('fastapi', 'FastAPI', 'framework detected in manifest');
  if (has('spring')) add('spring', 'Spring', 'framework detected in manifest');
  if (has('laravel')) add('laravel', 'Laravel', 'framework detected in manifest');
  if (has('rails')) add('rails', 'Rails', 'framework detected in manifest');
  if (has('wordpress')) add('wordpress', 'WordPress', 'framework detected');
  for (const lang of profile.languages) {
    const n = lang.language;
    if (n === 'JavaScript' || n === 'TypeScript')
      add('node', 'JavaScript/TypeScript', `${lang.files} file(s)`);
    else if (n === 'Python') add('python', 'Python', `${lang.files} file(s)`);
    else if (n === 'Java' || n === 'Kotlin') add('java', 'Java/Kotlin', `${lang.files} file(s)`);
    else if (n === 'PHP') add('php', 'PHP', `${lang.files} file(s)`);
    else if (n === 'Ruby') add('ruby', 'Ruby', `${lang.files} file(s)`);
    else if (n === 'C#') add('dotnet', '.NET', `${lang.files} file(s)`);
    else if (n === 'Go') add('go', 'Go', `${lang.files} file(s)`);
    else if (n === 'Terraform') add('terraform', 'Terraform', `${lang.files} file(s)`);
  }
  const paths = inventory.files.map((f) => f.path);
  if (paths.some((p) => /(^|\/)Dockerfile[\w.-]*$/.test(p)))
    add('docker', 'Docker', 'Dockerfile present');
  if (paths.some((p) => /^\.github\/workflows\//.test(p)))
    add('github-actions', 'GitHub Actions', 'workflow files present');
  if (paths.some((p) => /(^|\/)nginx[\w.-]*\.conf$/.test(p)))
    add('nginx', 'nginx', 'nginx config present');
  return out;
}

export function mergeStacks(...lists: Detected[][]): StackInfo {
  const seen = new Set<StackKey>();
  const detected: Detected[] = [];
  for (const list of lists)
    for (const d of list)
      if (!seen.has(d.stack)) {
        seen.add(d.stack);
        detected.push(d);
      }
  return { detected };
}
