import type { Finding, FixBundle, StackKey } from '../core/types.js';

const HEADER_KBS = new Set([
  'csp-missing',
  'csp-weak',
  'hsts-missing',
  'hsts-weak',
  'xcto-missing',
  'clickjacking',
  'referrer-policy',
  'permissions-policy',
  'info-disclosure-headers',
]);

interface HeaderSet {
  names: Array<[string, string]>;
  covers: string[];
}

function headerSet(findings: readonly Finding[], https: boolean): HeaderSet {
  const kbs = new Set(findings.filter((f) => HEADER_KBS.has(f.kb)).map((f) => f.kb));
  const names: Array<[string, string]> = [];
  const covers = findings.filter((f) => HEADER_KBS.has(f.kb)).map((f) => f.id);
  if (kbs.has('csp-missing') || kbs.has('csp-weak'))
    names.push([
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'",
    ]);
  if (https && (kbs.has('hsts-missing') || kbs.has('hsts-weak')))
    names.push(['Strict-Transport-Security', 'max-age=31536000; includeSubDomains']);
  if (kbs.has('xcto-missing')) names.push(['X-Content-Type-Options', 'nosniff']);
  if (kbs.has('clickjacking')) names.push(['X-Frame-Options', 'SAMEORIGIN']);
  if (kbs.has('referrer-policy'))
    names.push(['Referrer-Policy', 'strict-origin-when-cross-origin']);
  if (kbs.has('permissions-policy'))
    names.push(['Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()']);
  return { names, covers };
}

const NOTE_CSP =
  'The CSP is a strict starting point: if the page uses inline scripts or third-party hosts, deploy it first as Content-Security-Policy-Report-Only, review the console, then enforce.';

export function buildBundles(
  findings: readonly Finding[],
  stacks: readonly StackKey[],
  https: boolean,
): FixBundle[] {
  const bundles: FixBundle[] = [];
  const headers = headerSet(findings, https);
  if (headers.names.length > 0) {
    const targets: StackKey[] = [];
    for (const s of [
      'nginx',
      'apache',
      'caddy',
      'iis',
      'express',
      'nextjs',
      'django',
    ] as StackKey[])
      if (stacks.includes(s)) targets.push(s);
    if (targets.length === 0) targets.push('nginx', 'apache');
    for (const stack of targets) {
      const bundle = renderHeaders(stack, headers);
      if (bundle)
        bundles.push({
          ...bundle,
          covers: headers.covers,
          note: headers.names.some(([n]) => n === 'Content-Security-Policy')
            ? NOTE_CSP
            : 'Apply and reload the server.',
        });
    }
  }

  const exposure = findings.filter((f) =>
    ['exposed-git', 'exposed-env', 'exposed-backup', 'exposed-config-file'].includes(f.kb),
  );
  if (exposure.length > 0) {
    const nginx = stacks.includes('nginx') || !stacks.includes('apache');
    bundles.push(
      nginx
        ? {
            title: 'Block dot-files, backups and VCS folders',
            stack: 'nginx',
            language: 'nginx',
            location: 'nginx.conf (server block)',
            code: `location ~ /\\.(?!well-known) { deny all; return 404; }\nlocation ~* \\.(sql|bak|old|orig|swp|zip|tar|gz)$ { deny all; return 404; }`,
            covers: exposure.map((f) => f.id),
            note: 'This blocks the paths but does not undo exposure that already happened: rotate any secrets that were reachable.',
          }
        : {
            title: 'Block dot-files, backups and VCS folders',
            stack: 'apache',
            language: 'apache',
            location: '.htaccess or virtual host',
            code: `<FilesMatch "^\\.(?!well-known)">\n  Require all denied\n</FilesMatch>\n<FilesMatch "\\.(sql|bak|old|orig|swp|zip|tar|gz)$">\n  Require all denied\n</FilesMatch>`,
            covers: exposure.map((f) => f.id),
            note: 'This blocks the paths but does not undo exposure that already happened: rotate any secrets that were reachable.',
          },
    );
  }

  const info = findings.filter((f) => f.kb === 'info-disclosure-headers');
  if (info.length > 0 && (stacks.includes('nginx') || stacks.includes('apache'))) {
    bundles.push(
      stacks.includes('nginx')
        ? {
            title: 'Hide server version',
            stack: 'nginx',
            language: 'nginx',
            location: 'nginx.conf (http block)',
            code: `server_tokens off;\nproxy_hide_header X-Powered-By;`,
            covers: info.map((f) => f.id),
            note: 'Reload nginx afterwards.',
          }
        : {
            title: 'Hide server version',
            stack: 'apache',
            language: 'apache',
            location: 'httpd.conf',
            code: `ServerTokens Prod\nServerSignature Off\nHeader unset X-Powered-By`,
            covers: info.map((f) => f.id),
            note: 'Reload Apache afterwards.',
          },
    );
  }
  return bundles;
}

function renderHeaders(stack: StackKey, set: HeaderSet): Omit<FixBundle, 'covers' | 'note'> | null {
  const q = (s: string): string => s.replace(/"/g, '\\"');
  switch (stack) {
    case 'nginx':
      return {
        title: 'Security headers for nginx',
        stack,
        language: 'nginx',
        location: 'nginx.conf (server block, or an included snippet)',
        code: set.names.map(([n, v]) => `add_header ${n} "${q(v)}" always;`).join('\n'),
      };
    case 'apache':
      return {
        title: 'Security headers for Apache',
        stack,
        language: 'apache',
        location: 'virtual host or .htaccess (needs mod_headers)',
        code: `<IfModule mod_headers.c>\n${set.names.map(([n, v]) => `  Header always set ${n} "${q(v)}"`).join('\n')}\n</IfModule>`,
      };
    case 'caddy':
      return {
        title: 'Security headers for Caddy',
        stack,
        language: 'caddy',
        location: 'Caddyfile (site block)',
        code: `header {\n${set.names.map(([n, v]) => `  ${n} "${q(v)}"`).join('\n')}\n}`,
      };
    case 'iis':
      return {
        title: 'Security headers for IIS',
        stack,
        language: 'xml',
        location: 'web.config',
        code: `<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n${set.names.map(([n, v]) => `      <add name="${n}" value="${v.replace(/"/g, '&quot;')}" />`).join('\n')}\n    </customHeaders>\n  </httpProtocol>\n</system.webServer>`,
      };
    case 'express':
      return {
        title: 'Security headers for Express (helmet)',
        stack,
        language: 'javascript',
        location: 'app entry file, before routes',
        code: `import helmet from 'helmet';\napp.use(helmet());   // sets most headers with safe defaults\napp.use((req, res, next) => {\n${set.names
          .filter(([n]) => n === 'Permissions-Policy' || n === 'Content-Security-Policy')
          .map(([n, v]) => `  res.setHeader('${n}', ${JSON.stringify(v)});`)
          .join('\n')}\n  next();\n});`,
      };
    case 'nextjs':
      return {
        title: 'Security headers for Next.js',
        stack,
        language: 'javascript',
        location: 'next.config.js',
        code: `module.exports = {\n  async headers() {\n    return [{\n      source: '/(.*)',\n      headers: [\n${set.names.map(([n, v]) => `        { key: '${n}', value: ${JSON.stringify(v)} },`).join('\n')}\n      ],\n    }];\n  },\n};`,
      };
    case 'django':
      return {
        title: 'Security settings for Django',
        stack,
        language: 'python',
        location: 'settings.py',
        code: `SECURE_HSTS_SECONDS = 31536000\nSECURE_HSTS_INCLUDE_SUBDOMAINS = True\nSECURE_CONTENT_TYPE_NOSNIFF = True\nX_FRAME_OPTIONS = 'SAMEORIGIN'\nSECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'\n# CSP: pip install django-csp, then set CONTENT_SECURITY_POLICY`,
      };
    default:
      return null;
  }
}
