import type { CodeExample, Effort } from '../../core/types.js';

export interface Topic {
  cwe: string[];
  /** OWASP Top 10 (2021) category ids, for example `A03`. */
  owasp: string[];
  effort: Effort;
  summary: string;
  why: string;
  steps: string[];
  examples: CodeExample[];
  verify: string;
  references: string[];
}

export type TopicMap = Record<string, Topic>;

export const OWASP_NAMES: Record<string, string> = {
  A01: 'A01:2021 Broken Access Control',
  A02: 'A02:2021 Cryptographic Failures',
  A03: 'A03:2021 Injection',
  A04: 'A04:2021 Insecure Design',
  A05: 'A05:2021 Security Misconfiguration',
  A06: 'A06:2021 Vulnerable and Outdated Components',
  A07: 'A07:2021 Identification and Authentication Failures',
  A08: 'A08:2021 Software and Data Integrity Failures',
  A09: 'A09:2021 Security Logging and Monitoring Failures',
  A10: 'A10:2021 Server-Side Request Forgery',
};

export function ex(
  stack: CodeExample['stack'],
  language: string,
  label: string,
  code: string,
): CodeExample {
  return { stack, language, label, code: code.replace(/^\n/, '').replace(/\s+$/, '') };
}

const MDN = 'https://developer.mozilla.org/en-US/docs/Web/Security';
export const REF = {
  owasp: (path: string): string => `https://cheatsheetseries.owasp.org/cheatsheets/${path}.html`,
  cwe: (n: number): string => `https://cwe.mitre.org/data/definitions/${n}.html`,
  mdn: (path: string): string => `https://developer.mozilla.org/en-US/docs/${path}`,
  mdnSecurity: MDN,
};
