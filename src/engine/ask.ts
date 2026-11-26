import type { CodeExample, StackKey } from '../core/types.js';
import { TOPICS } from './advisor.js';
import { compatibleKeys } from './stack.js';
import type { Topic } from './kb/types.js';

/**
 * Kinga Advisor: the built-in, offline assistant. It runs on the bundled security knowledge base,
 * with no network access and no external model. It answers by matching the question against topics
 * (including common abbreviations) and tailoring the examples to technologies named in the question.
 */

const SYNONYMS: Record<string, string[]> = {
  sqli: ['sql-injection'],
  sql: ['sql-injection'],
  xss: ['xss-dom', 'xss-reflected', 'xss-framework-bypass', 'csp-missing'],
  'cross-site': ['xss-reflected', 'csrf-token-missing'],
  csrf: ['csrf-token-missing', 'cookie-samesite'],
  xsrf: ['csrf-token-missing'],
  cors: ['cors-misconfig', 'cors-code'],
  jwt: ['jwt-misuse'],
  token: ['jwt-misuse', 'insecure-random'],
  ssrf: ['ssrf'],
  xxe: ['xxe'],
  rce: ['command-injection', 'code-eval', 'insecure-deserialization', 'ssti'],
  shell: ['command-injection'],
  exec: ['command-injection', 'code-eval'],
  eval: ['code-eval'],
  injection: ['sql-injection', 'command-injection', 'nosql-injection', 'ssti'],
  ssl: ['no-https', 'tls-cert-untrusted', 'tls-legacy-protocol'],
  tls: ['tls-legacy-protocol', 'tls-cert-untrusted', 'no-https'],
  https: ['no-https', 'http-no-redirect', 'hsts-missing'],
  hsts: ['hsts-missing'],
  certificate: ['tls-cert-expired', 'tls-cert-untrusted', 'tls-cert-hostname'],
  cert: ['tls-cert-expired', 'tls-cert-untrusted'],
  header: ['csp-missing', 'hsts-missing', 'xcto-missing', 'clickjacking'],
  headers: ['csp-missing', 'hsts-missing', 'xcto-missing', 'clickjacking', 'referrer-policy'],
  csp: ['csp-missing', 'csp-weak'],
  clickjacking: ['clickjacking'],
  iframe: ['clickjacking'],
  cookie: ['cookie-secure', 'cookie-httponly', 'cookie-samesite'],
  cookies: ['cookie-secure', 'cookie-httponly', 'cookie-samesite'],
  session: ['insecure-session-cookie', 'weak-session-secret', 'cookie-secure'],
  password: ['password-storage', 'hardcoded-secret', 'password-over-http'],
  passwords: ['password-storage'],
  hash: ['weak-hash', 'password-storage'],
  md5: ['weak-hash', 'password-storage'],
  sha1: ['weak-hash'],
  encryption: ['weak-cipher', 'hardcoded-iv'],
  encrypt: ['weak-cipher'],
  random: ['insecure-random'],
  secret: ['hardcoded-secret', 'secret-file-committed', 'secret-in-page'],
  secrets: ['hardcoded-secret', 'secret-file-committed'],
  apikey: ['hardcoded-secret'],
  env: ['exposed-env', 'secret-file-committed'],
  git: ['exposed-git', 'secret-file-committed'],
  upload: ['unsafe-upload'],
  path: ['path-traversal'],
  traversal: ['path-traversal'],
  redirect: ['open-redirect', 'https-downgrade'],
  deserialization: ['insecure-deserialization'],
  pickle: ['insecure-deserialization'],
  yaml: ['insecure-deserialization'],
  docker: ['docker-root', 'docker-unpinned', 'docker-secret-layer', 'container-privileged'],
  container: ['docker-root', 'container-privileged', 'k8s-security-context'],
  kubernetes: ['k8s-security-context', 'k8s-host-namespace'],
  k8s: ['k8s-security-context'],
  terraform: ['terraform-open-ingress', 'terraform-public-bucket', 'terraform-wildcard-iam'],
  s3: ['terraform-public-bucket'],
  dependency: ['vulnerable-dependency', 'no-lockfile', 'unpinned-dependency'],
  dependencies: ['vulnerable-dependency', 'no-lockfile'],
  npm: ['vulnerable-dependency', 'no-lockfile', 'install-script'],
  lockfile: ['no-lockfile'],
  outdated: ['eol-software', 'vulnerable-dependency'],
  debug: ['debug-enabled', 'exposed-debug'],
  errors: ['verbose-errors', 'verbose-errors-code'],
  logging: ['sensitive-logging'],
  logs: ['sensitive-logging'],
  regex: ['regex-dos'],
  redos: ['regex-dos'],
  actions: ['github-actions-injection', 'github-actions-pinning', 'github-actions-permissions'],
  github: ['github-actions-injection', 'github-actions-pinning'],
  sri: ['sri-missing'],
  integrity: ['sri-missing'],
  sourcemap: ['sourcemap-exposed'],
};

const STACK_WORDS: Record<string, StackKey> = {
  node: 'node',
  nodejs: 'node',
  javascript: 'node',
  typescript: 'node',
  express: 'express',
  next: 'nextjs',
  nextjs: 'nextjs',
  python: 'python',
  django: 'django',
  flask: 'flask',
  fastapi: 'fastapi',
  java: 'java',
  spring: 'spring',
  kotlin: 'java',
  php: 'php',
  laravel: 'laravel',
  wordpress: 'wordpress',
  ruby: 'ruby',
  rails: 'rails',
  dotnet: 'dotnet',
  csharp: 'dotnet',
  asp: 'dotnet',
  iis: 'iis',
  go: 'go',
  golang: 'go',
  nginx: 'nginx',
  apache: 'apache',
  caddy: 'caddy',
  docker: 'docker',
  kubernetes: 'kubernetes',
  k8s: 'kubernetes',
  terraform: 'terraform',
};

const STOP = new Set([
  'the',
  'a',
  'an',
  'how',
  'do',
  'i',
  'to',
  'in',
  'on',
  'my',
  'is',
  'it',
  'of',
  'for',
  'and',
  'or',
  'what',
  'why',
  'can',
  'fix',
  'with',
  'this',
  'that',
  'are',
  'should',
  'does',
  'use',
  'using',
  'secure',
  'prevent',
  'protect',
  'avoid',
]);

export interface AskAnswer {
  topic: string;
  summary: string;
  why: string;
  steps: string[];
  examples: CodeExample[];
  verify: string;
  references: string[];
  cwe: string[];
  score: number;
}

export interface AskResult {
  answers: AskAnswer[];
  stacks: StackKey[];
}

function tokens(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9#+. -]/g, ' ')
    .split(/[\s-]+/)
    .map((t) => t.replace(/^\.+|\.+$/g, ''))
    .filter((t) => t.length > 1 && !STOP.has(t));
}

function score(question: string[], key: string, topic: Topic): number {
  let total = 0;
  const keyWords = new Set(key.split('-'));
  const body = new Set(tokens(`${topic.summary} ${topic.why}`));
  for (const w of question) {
    if (keyWords.has(w)) total += 4;
    if (body.has(w)) total += 1;
    if (SYNONYMS[w]?.includes(key)) total += 6;
    if (w === key) total += 10;
  }
  return total;
}

export function ask(question: string, limit = 2): AskResult {
  const words = tokens(question);
  const stacks = [
    ...new Set(words.map((w) => STACK_WORDS[w]).filter((s): s is StackKey => s !== undefined)),
  ];
  const ranked = Object.entries(TOPICS)
    .map(([key, topic]) => ({ key, topic, score: score(words, key, topic) }))
    .filter((r) => r.score > 0)
    .sort((a, b) => b.score - a.score || a.key.localeCompare(b.key))
    .slice(0, limit);
  const compatible = compatibleKeys(stacks);
  return {
    stacks,
    answers: ranked.map(({ key, topic, score: s }) => {
      const matching = topic.examples.filter((e) => compatible.has(e.stack));
      const generic = topic.examples.filter((e) => e.stack === 'generic');
      const examples =
        stacks.length > 0 && matching.length > 0
          ? [...matching, ...generic]
          : topic.examples.slice(0, 3);
      return {
        topic: key,
        summary: topic.summary,
        why: topic.why,
        steps: topic.steps,
        examples,
        verify: topic.verify,
        references: topic.references,
        cwe: topic.cwe,
        score: s,
      };
    }),
  };
}

export function listTopics(): Array<{ key: string; summary: string; cwe: string[] }> {
  return Object.entries(TOPICS)
    .map(([key, t]) => ({ key, summary: t.summary, cwe: t.cwe }))
    .sort((a, b) => a.key.localeCompare(b.key));
}

export function getTopic(key: string): Topic | undefined {
  return TOPICS[key];
}
