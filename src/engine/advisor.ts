import type {
  Advice,
  CodeExample,
  Confidence,
  Effort,
  Finding,
  RawFinding,
  Severity,
  StackKey,
} from '../core/types.js';
import { CODE_TOPICS } from './kb/code.js';
import { INFRA_TOPICS } from './kb/infra.js';
import { OWASP_NAMES, type Topic, type TopicMap } from './kb/types.js';
import { WEB_TOPICS } from './kb/web.js';
import { compatibleKeys } from './stack.js';
import { createHash } from 'node:crypto';

export const TOPICS: TopicMap = { ...WEB_TOPICS, ...CODE_TOPICS, ...INFRA_TOPICS };

const FALLBACK: Topic = {
  cwe: [],
  owasp: [],
  effort: 'hours',
  summary:
    'Review this finding and apply the vendor or framework guidance for the affected component.',
  why: 'This pattern is commonly associated with security weaknesses.',
  steps: [
    'Confirm the issue applies to your deployment.',
    'Apply the fix recommended by your framework or vendor.',
    'Re-run Kinga to confirm it no longer appears.',
  ],
  examples: [],
  verify: 'Re-run Kinga and confirm the finding is gone.',
  references: ['https://owasp.org/Top10/'],
};

const SEVERITY_BASE: Record<Severity, number> = {
  critical: 92,
  high: 74,
  medium: 48,
  low: 22,
  info: 6,
};
const CONFIDENCE_FACTOR: Record<Confidence, number> = { high: 1, medium: 0.88, low: 0.68 };

/** 0-100: how soon this should be fixed. Mixes severity, certainty, whether it was observed, and context. */
export function riskScore(f: RawFinding): number {
  let score = SEVERITY_BASE[f.severity] * CONFIDENCE_FACTOR[f.confidence];
  if (f.verified) score += 4;
  if (f.domain === 'secrets') score += 4;
  if (f.domain === 'web' && f.facts?.['local'] !== true) score += 3;
  if (
    f.domain !== 'web' &&
    /(^|\/)(tests?|__tests__|spec|examples?|docs?|fixtures?)\//i.test(f.target)
  )
    score -= 15;
  return Math.max(0, Math.min(100, Math.round(score)));
}

export function fingerprint(f: RawFinding): string {
  const key = [
    f.rule,
    f.target,
    f.line ?? '',
    f.domain === 'web' ? '' : f.evidence.slice(0, 80),
  ].join('|');
  return createHash('sha256').update(key).digest('hex').slice(0, 16);
}

function topicFor(kb: string): Topic {
  return TOPICS[kb] ?? FALLBACK;
}

/** Examples for the detected stack first, then generic ones; unknown stack gets a short selection. */
const ECOSYSTEM_STACK: Record<string, StackKey> = { npm: 'node', pypi: 'python', maven: 'java' };

function chooseExamples(
  allExamples: readonly CodeExample[],
  stacks: readonly StackKey[],
  ecosystem?: string,
): CodeExample[] {
  // A dependency finding already knows its ecosystem; only show that package manager's commands.
  const forced = ecosystem ? ECOSYSTEM_STACK[ecosystem] : undefined;
  const examples = forced
    ? allExamples.filter((e) => e.stack === forced || e.stack === 'generic')
    : allExamples;
  if (forced) return [...examples];
  if (examples.length === 0) return [];
  const compatible = compatibleKeys(stacks);
  const matching = examples.filter((e) => compatible.has(e.stack));
  const generic = examples.filter((e) => e.stack === 'generic');
  const picked = [...matching, ...generic.filter((g) => !matching.includes(g))];
  if (matching.length > 0) return picked.slice(0, 4);
  return examples.slice(0, 3);
}

function fillPlaceholders(text: string, facts: RawFinding['facts']): string {
  if (!facts) return text;
  return text
    .replace(/<package>/g, String(facts['package'] ?? '<package>'))
    .replace(/<fixed-version>/g, String(facts['fixedIn'] ?? '<fixed-version>'));
}

export function buildAdvice(raw: RawFinding, stacks: readonly StackKey[]): Advice {
  const topic = topicFor(raw.kb);
  let summary = topic.summary;
  let steps = [...topic.steps];
  const facts = raw.facts;

  // Finding-specific tailoring: the engine rewrites generic advice using what the scanner observed.
  if (raw.kb === 'vulnerable-dependency' || raw.kb === 'vulnerable-js-library') {
    const pkg = String(facts?.['package'] ?? '');
    const fixed = String(facts?.['fixedIn'] ?? '');
    const advisory = String(facts?.['advisory'] ?? '');
    if (pkg && fixed) {
      summary = `Upgrade ${pkg} to ${fixed} or newer${advisory ? ` to fix ${advisory}` : ''}.`;
      steps = [`Upgrade ${pkg} to at least ${fixed}.`, ...steps.slice(1)];
    }
  }
  if (facts?.['cookie'] && raw.kb.startsWith('cookie-')) {
    const name = String(facts['cookie']);
    summary = `${summary.replace(/\.$/, '')} (cookie "${name}").`;
    if (facts['session'] === true)
      steps = [`"${name}" looks like a session cookie, so fix it first.`, ...steps];
  }

  return {
    summary: fillPlaceholders(summary, facts),
    why: topic.why,
    steps: steps.map((s) => fillPlaceholders(s, facts)),
    examples: chooseExamples(
      topic.examples,
      stacks,
      typeof facts?.['ecosystem'] === 'string' ? facts['ecosystem'] : undefined,
    ).map((e) => ({
      ...e,
      code: fillPlaceholders(e.code, facts),
    })),
    verify: topic.verify,
    references: topic.references,
    effort: topic.effort,
  };
}

export function standardsFor(
  raw: RawFinding,
  extraCwe: readonly string[] = [],
): { cwe: string[]; owasp: string[] } {
  const topic = topicFor(raw.kb);
  const cwe = [
    ...new Set([...topic.cwe, ...(raw.tags ?? []).filter((t) => /^CWE-\d+$/.test(t)), ...extraCwe]),
  ];
  const owasp = topic.owasp.map((id) => OWASP_NAMES[id] ?? id);
  return { cwe, owasp };
}

export function effortRank(e: Effort): number {
  return e === 'minutes' ? 0 : e === 'hours' ? 1 : 2;
}

export function toFinding(raw: RawFinding, id: string, stacks: readonly StackKey[]): Finding {
  return {
    ...raw,
    id,
    ...standardsFor(raw),
    risk: riskScore(raw),
    advice: buildAdvice(raw, stacks),
    fingerprint: fingerprint(raw),
  };
}
