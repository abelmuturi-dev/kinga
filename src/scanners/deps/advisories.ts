import { readFile } from 'node:fs/promises';
import { isRecord } from '../../util/json.js';
import { isSeverity, type Severity } from '../../core/types.js';
import { inRange, parseRanges, type VersionRange } from './version.js';

export type Ecosystem = 'npm' | 'pypi' | 'maven';

export interface Advisory {
  id: string;
  ecosystem: Ecosystem;
  package: string;
  ranges: VersionRange[];
  severity: Severity;
  summary: string;
  cwe?: string[];
}

export interface AdvisoryHit {
  advisory: Advisory;
  /** First fixed version in the range that matched. */
  fixedIn: string;
}

/** [ecosystem, package, id, affected ranges, severity, summary, cwe?] */
type Row = [Ecosystem, string, string, string, Severity, string, string?];

/**
 * A curated snapshot of widely exploited or high-impact advisories. It is deliberately small and is
 * NOT a complete vulnerability database: run `npm audit`, `pip-audit` or OSV-Scanner for full
 * coverage, and add your own entries with `advisories` in kinga.config.json.
 */
const ROWS: Row[] = [
  // npm
  [
    'npm',
    'lodash',
    'CVE-2020-8203',
    '<4.17.19',
    'high',
    'Prototype pollution in zipObjectDeep',
    'CWE-1321',
  ],
  [
    'npm',
    'lodash',
    'CVE-2021-23337',
    '<4.17.21',
    'high',
    'Command injection through the template function',
    'CWE-94',
  ],
  [
    'npm',
    'minimist',
    'CVE-2021-44906',
    '<0.2.4 || >=1.0.0 <1.2.6',
    'critical',
    'Prototype pollution via crafted arguments',
    'CWE-1321',
  ],
  [
    'npm',
    'node-fetch',
    'CVE-2022-0235',
    '<2.6.7 || >=3.0.0 <3.1.1',
    'high',
    'Forwards sensitive headers to third-party hosts on redirect',
    'CWE-200',
  ],
  [
    'npm',
    'jsonwebtoken',
    'CVE-2022-23529',
    '<9.0.0',
    'high',
    'Several token-verification flaws, including unsafe key handling',
    'CWE-20',
  ],
  [
    'npm',
    'handlebars',
    'CVE-2021-23369',
    '<4.7.7',
    'critical',
    'Remote code execution when compiling untrusted templates',
    'CWE-94',
  ],
  [
    'npm',
    'moment',
    'CVE-2022-31129',
    '<2.29.4',
    'high',
    'Regular-expression denial of service when parsing dates',
    'CWE-1333',
  ],
  [
    'npm',
    'serialize-javascript',
    'CVE-2020-7660',
    '<3.1.0',
    'high',
    'Code injection through insecure serialization',
    'CWE-502',
  ],
  [
    'npm',
    'ejs',
    'CVE-2022-29078',
    '<3.1.7',
    'critical',
    'Template injection leading to remote code execution',
    'CWE-94',
  ],
  [
    'npm',
    'jquery',
    'CVE-2020-11022',
    '<3.5.0',
    'medium',
    'Cross-site scripting in htmlPrefilter / DOM manipulation methods',
    'CWE-79',
  ],
  [
    'npm',
    'express',
    'CVE-2024-29041',
    '<4.19.2',
    'medium',
    'Open redirect through malformed URLs in res.location / res.redirect',
    'CWE-601',
  ],
  [
    'npm',
    'axios',
    'CVE-2024-39338',
    '>=1.3.2 <1.7.4',
    'high',
    'Server-side request forgery through path-relative URLs',
    'CWE-918',
  ],
  [
    'npm',
    'axios',
    'CVE-2023-45857',
    '>=0.8.1 <1.6.0',
    'medium',
    'Leaks the XSRF-TOKEN cookie value in a request header to any host',
    'CWE-352',
  ],
  [
    'npm',
    'ws',
    'CVE-2024-37890',
    '<5.2.4 || >=6.0.0 <6.2.3 || >=7.0.0 <7.5.10 || >=8.0.0 <8.17.1',
    'high',
    'Denial of service with many HTTP headers',
    'CWE-476',
  ],
  [
    'npm',
    'braces',
    'CVE-2024-4068',
    '<3.0.3',
    'high',
    'Uncontrolled resource consumption on unbalanced braces',
    'CWE-1050',
  ],
  [
    'npm',
    'micromatch',
    'CVE-2024-4067',
    '<4.0.8',
    'medium',
    'Regular-expression denial of service',
    'CWE-1333',
  ],
  [
    'npm',
    'follow-redirects',
    'CVE-2024-28849',
    '<1.15.6',
    'medium',
    'Leaks the Proxy-Authorization header across hosts',
    'CWE-200',
  ],
  [
    'npm',
    'semver',
    'CVE-2022-25883',
    '<5.7.2 || >=6.0.0 <6.3.1 || >=7.0.0 <7.5.2',
    'high',
    'Regular-expression denial of service',
    'CWE-1333',
  ],
  [
    'npm',
    'word-wrap',
    'CVE-2023-26115',
    '<1.2.4',
    'medium',
    'Regular-expression denial of service',
    'CWE-1333',
  ],
  [
    'npm',
    'json5',
    'CVE-2022-46175',
    '<1.0.2 || >=2.0.0 <2.2.2',
    'high',
    'Prototype pollution through JSON5.parse',
    'CWE-1321',
  ],
  [
    'npm',
    'tough-cookie',
    'CVE-2023-26136',
    '<4.1.3',
    'medium',
    'Prototype pollution in cookie memstore',
    'CWE-1321',
  ],
  [
    'npm',
    'underscore',
    'CVE-2021-23358',
    '>=1.3.2 <1.12.1',
    'high',
    'Arbitrary code execution through the template function',
    'CWE-94',
  ],
  [
    'npm',
    'glob-parent',
    'CVE-2020-28469',
    '<5.1.2',
    'high',
    'Regular-expression denial of service',
    'CWE-1333',
  ],
  ['npm', 'shelljs', 'CVE-2022-0144', '<0.8.5', 'high', 'Improper privilege management', 'CWE-269'],
  [
    'npm',
    'nth-check',
    'CVE-2021-3803',
    '<2.0.1',
    'high',
    'Regular-expression denial of service',
    'CWE-1333',
  ],
  [
    'npm',
    'postcss',
    'CVE-2023-44270',
    '<8.4.31',
    'medium',
    'Improper parsing of line returns',
    'CWE-74',
  ],
  [
    'npm',
    'bootstrap',
    'CVE-2019-8331',
    '<3.4.1 || >=4.0.0 <4.3.1',
    'medium',
    'Cross-site scripting in tooltip and popover templates',
    'CWE-79',
  ],
  [
    'npm',
    'got',
    'CVE-2022-33987',
    '<11.8.5 || >=12.0.0 <12.1.0',
    'medium',
    'Redirects to a UNIX socket are followed',
    'CWE-601',
  ],
  [
    'npm',
    'xml2js',
    'CVE-2023-0842',
    '<0.5.0',
    'medium',
    'Prototype pollution when parsing XML',
    'CWE-1321',
  ],
  [
    'npm',
    'ip',
    'CVE-2023-42282',
    '<1.1.9 || >=2.0.0 <2.0.1',
    'high',
    'isPublic misclassifies private addresses (SSRF)',
    'CWE-918',
  ],
  [
    'npm',
    'crypto-js',
    'CVE-2023-46233',
    '<4.2.0',
    'critical',
    'PBKDF2 defaults are far weaker than intended',
    'CWE-916',
  ],
  [
    'npm',
    'webpack-dev-middleware',
    'CVE-2024-29180',
    '<5.3.4 || >=6.0.0 <6.1.2 || >=7.0.0 <7.1.0',
    'high',
    'Path traversal reads files outside the served directory',
    'CWE-22',
  ],
  [
    'npm',
    'body-parser',
    'CVE-2024-45590',
    '<1.20.3',
    'high',
    'Denial of service with crafted URL-encoded bodies',
    'CWE-405',
  ],
  [
    'npm',
    'cookie',
    'CVE-2024-47764',
    '<0.7.0',
    'low',
    'Accepts out-of-bounds characters in cookie names and values',
    'CWE-74',
  ],
  [
    'npm',
    'next',
    'CVE-2025-29927',
    '>=11.1.4 <12.3.5 || >=13.0.0 <13.5.9 || >=14.0.0 <14.2.25 || >=15.0.0 <15.2.3',
    'critical',
    'Middleware authorization can be bypassed with a crafted header',
    'CWE-285',
  ],
  // PyPI
  [
    'pypi',
    'pyyaml',
    'CVE-2020-14343',
    '<5.4',
    'critical',
    'Arbitrary code execution when loading untrusted YAML',
    'CWE-502',
  ],
  [
    'pypi',
    'requests',
    'CVE-2023-32681',
    '<2.31.0',
    'medium',
    'Leaks the Proxy-Authorization header to the destination server',
    'CWE-200',
  ],
  [
    'pypi',
    'urllib3',
    'CVE-2021-33503',
    '<1.26.5',
    'high',
    'Regular-expression denial of service in URL authority parsing',
    'CWE-1333',
  ],
  [
    'pypi',
    'urllib3',
    'CVE-2023-45803',
    '<1.26.18 || >=2.0.0 <2.0.7',
    'medium',
    'Request body is not removed when following a redirect',
    'CWE-200',
  ],
  [
    'pypi',
    'flask',
    'CVE-2023-30861',
    '<2.2.5 || >=2.3.0 <2.3.2',
    'high',
    'Session cookie can be cached and served to another user by a proxy',
    'CWE-539',
  ],
  [
    'pypi',
    'jinja2',
    'CVE-2024-34064',
    '<3.1.4',
    'medium',
    'Cross-site scripting through the xmlattr filter',
    'CWE-79',
  ],
  [
    'pypi',
    'pillow',
    'CVE-2023-4863',
    '<10.0.1',
    'high',
    'Heap buffer overflow in the bundled libwebp',
    'CWE-787',
  ],
  [
    'pypi',
    'cryptography',
    'CVE-2023-50782',
    '<42.0.0',
    'high',
    'Bleichenbacher timing oracle in RSA decryption',
    'CWE-208',
  ],
  [
    'pypi',
    'werkzeug',
    'CVE-2024-34069',
    '<3.0.3',
    'high',
    'Debugger can be abused for remote code execution',
    'CWE-94',
  ],
  [
    'pypi',
    'paramiko',
    'CVE-2023-48795',
    '<3.4.0',
    'medium',
    'Terrapin attack weakens SSH connection security',
    'CWE-354',
  ],
  [
    'pypi',
    'setuptools',
    'CVE-2024-6345',
    '<70.0.0',
    'high',
    'Remote code execution through package_index download functions',
    'CWE-94',
  ],
  [
    'pypi',
    'certifi',
    'CVE-2023-37920',
    '<2023.7.22',
    'high',
    'Trusts a removed root certificate authority',
    'CWE-345',
  ],
  [
    'pypi',
    'gunicorn',
    'CVE-2024-1135',
    '<22.0.0',
    'high',
    'HTTP request smuggling through Transfer-Encoding handling',
    'CWE-444',
  ],
  [
    'pypi',
    'aiohttp',
    'CVE-2024-23334',
    '<3.9.2',
    'high',
    'Path traversal when static routes follow symlinks',
    'CWE-22',
  ],
  [
    'pypi',
    'sqlparse',
    'CVE-2024-4340',
    '<0.5.0',
    'high',
    'Denial of service with deeply nested statements',
    'CWE-674',
  ],
  [
    'pypi',
    'pyjwt',
    'CVE-2022-29217',
    '<2.4.0',
    'high',
    'Key confusion lets an attacker choose the verification algorithm',
    'CWE-327',
  ],
  [
    'pypi',
    'python-jose',
    'CVE-2024-33663',
    '<3.4.0',
    'high',
    'Algorithm confusion with ECDSA keys',
    'CWE-327',
  ],
  [
    'pypi',
    'starlette',
    'CVE-2024-47874',
    '<0.40.0',
    'high',
    'Denial of service through unbounded multipart form fields',
    'CWE-770',
  ],
  // Maven (group:artifact)
  [
    'maven',
    'org.apache.logging.log4j:log4j-core',
    'CVE-2021-44228',
    '>=2.0.0 <2.17.1',
    'critical',
    'Log4Shell: remote code execution through JNDI lookups in logged data',
    'CWE-502',
  ],
  [
    'maven',
    'org.yaml:snakeyaml',
    'CVE-2022-1471',
    '<2.0',
    'critical',
    'Arbitrary code execution when parsing untrusted YAML',
    'CWE-502',
  ],
  [
    'maven',
    'org.apache.commons:commons-text',
    'CVE-2022-42889',
    '>=1.5 <1.10.0',
    'critical',
    'Text4Shell: code execution through string interpolation',
    'CWE-94',
  ],
  [
    'maven',
    'org.springframework:spring-beans',
    'CVE-2022-22965',
    '<5.2.20 || >=5.3.0 <5.3.18',
    'critical',
    'Spring4Shell: remote code execution through data binding',
    'CWE-94',
  ],
  [
    'maven',
    'org.springframework:spring-webmvc',
    'CVE-2022-22965',
    '<5.2.20 || >=5.3.0 <5.3.18',
    'critical',
    'Spring4Shell: remote code execution through data binding',
    'CWE-94',
  ],
  [
    'maven',
    'org.apache.struts:struts2-core',
    'CVE-2017-5638',
    '>=2.3.5 <2.3.32 || >=2.5.0 <2.5.10.1',
    'critical',
    'Remote code execution through the Content-Type header parser',
    'CWE-20',
  ],
];

function rowToAdvisory(row: Row): Advisory {
  const [ecosystem, pkg, id, spec, severity, summary, cwe] = row;
  return {
    id,
    ecosystem,
    package: pkg,
    ranges: parseRanges(spec),
    severity,
    summary,
    ...(cwe ? { cwe: [cwe] } : {}),
  };
}

export const BUNDLED_ADVISORIES: readonly Advisory[] = ROWS.map(rowToAdvisory);

export function normalizePackageName(ecosystem: Ecosystem, name: string): string {
  const lower = name.trim().toLowerCase();
  return ecosystem === 'pypi' ? lower.replace(/[_.]+/g, '-') : lower;
}

export class AdvisoryDb {
  private readonly byKey = new Map<string, Advisory[]>();

  constructor(advisories: readonly Advisory[] = BUNDLED_ADVISORIES) {
    for (const advisory of advisories) this.add(advisory);
  }

  add(advisory: Advisory): void {
    const key = `${advisory.ecosystem}:${normalizePackageName(advisory.ecosystem, advisory.package)}`;
    const list = this.byKey.get(key) ?? [];
    list.push(advisory);
    this.byKey.set(key, list);
  }

  get size(): number {
    let n = 0;
    for (const list of this.byKey.values()) n += list.length;
    return n;
  }

  lookup(ecosystem: Ecosystem, name: string, version: string): AdvisoryHit[] {
    const list = this.byKey.get(`${ecosystem}:${normalizePackageName(ecosystem, name)}`) ?? [];
    const hits: AdvisoryHit[] = [];
    for (const advisory of list) {
      const matched = advisory.ranges.find((r) => inRange(version, r));
      if (matched) hits.push({ advisory, fixedIn: matched.fixed });
    }
    return hits;
  }
}

/**
 * Loads extra advisories from a JSON file:
 * `[{ "id": "...", "ecosystem": "npm", "package": "x", "affected": "<1.2.3", "severity": "high", "summary": "..." }]`
 */
export async function loadAdvisoryFile(file: string): Promise<Advisory[]> {
  const raw: unknown = JSON.parse(await readFile(file, 'utf8'));
  if (!Array.isArray(raw)) throw new Error(`${file}: expected a JSON array of advisories`);
  const out: Advisory[] = [];
  raw.forEach((item: unknown, i) => {
    if (!isRecord(item)) throw new Error(`${file}: entry ${i} is not an object`);
    const { id, ecosystem, affected, severity, summary } = item;
    const pkg = item['package'];
    if (
      typeof id !== 'string' ||
      typeof pkg !== 'string' ||
      typeof affected !== 'string' ||
      typeof summary !== 'string' ||
      (ecosystem !== 'npm' && ecosystem !== 'pypi' && ecosystem !== 'maven') ||
      typeof severity !== 'string' ||
      !isSeverity(severity)
    )
      throw new Error(
        `${file}: entry ${i} needs id, ecosystem (npm|pypi|maven), package, affected, severity, summary`,
      );
    const ranges = parseRanges(affected);
    if (ranges.length === 0)
      throw new Error(`${file}: entry ${i} has an unusable "affected" range "${affected}"`);
    out.push({ id, ecosystem, package: pkg, ranges, severity, summary });
  });
  return out;
}
