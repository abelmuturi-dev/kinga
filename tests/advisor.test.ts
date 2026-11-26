import { describe, expect, it } from 'vitest';
import { buildAdvice, TOPICS } from '../src/engine/advisor.js';
import { ask } from '../src/engine/ask.js';
import { buildFixPlan } from '../src/engine/insights.js';
import { toFinding } from '../src/engine/advisor.js';
import type { RawFinding } from '../src/core/types.js';

const raw = (over: Partial<RawFinding>): RawFinding => ({
  rule: 'T-1',
  kb: 'sql-injection',
  title: 't',
  severity: 'high',
  confidence: 'medium',
  domain: 'code',
  category: 'injection',
  target: 'a.py',
  line: 1,
  evidence: 'e',
  verified: false,
  verification: 'v',
  ...over,
});

describe('knowledge base', () => {
  it('every topic has steps, a verify instruction and at least one reference or is explicitly unreachable', () => {
    for (const [key, t] of Object.entries(TOPICS)) {
      expect(t.summary.length, key).toBeGreaterThan(10);
      expect(t.verify.length, key).toBeGreaterThan(5);
      expect(t.steps.length, key).toBeGreaterThan(0);
    }
  });
});

describe('advice tailoring', () => {
  it('puts examples for the detected stack first', () => {
    const advice = buildAdvice(raw({}), ['django']);
    expect(advice.examples[0]?.stack).toMatch(/python|django/);
  });
  it('rewrites dependency advice with the fixed version', () => {
    const advice = buildAdvice(
      raw({
        kb: 'vulnerable-dependency',
        facts: { package: 'lodash', fixedIn: '4.17.21', advisory: 'CVE-X', ecosystem: 'npm' },
      }),
      ['python'],
    );
    expect(advice.summary).toContain('lodash 4.17.21'.replace(' ', ' to '));
    expect(advice.examples.every((e) => e.stack === 'node' || e.stack === 'generic')).toBe(true);
  });
});

describe('fix plan', () => {
  it('keeps different vulnerable packages as separate steps', () => {
    const a = toFinding(
      raw({ kb: 'vulnerable-dependency', facts: { package: 'a', fixedIn: '2', ecosystem: 'npm' } }),
      'x#1',
      [],
    );
    const b = toFinding(
      raw({ kb: 'vulnerable-dependency', facts: { package: 'b', fixedIn: '3', ecosystem: 'npm' } }),
      'x#2',
      [],
    );
    expect(buildFixPlan([a, b])).toHaveLength(2);
  });
  it('puts quick serious fixes ahead of slow ones of the same severity', () => {
    const slow = toFinding(raw({ kb: 'sql-injection' }), 's#1', []);
    const quick = toFinding(raw({ kb: 'tls-verification-disabled' }), 'q#1', []);
    const plan = buildFixPlan([slow, quick]);
    expect(plan[0]?.findingIds).toEqual(['q#1']);
  });
});

describe('Kinga Advisor (offline Q&A)', () => {
  it('answers a SQL injection question with matching-stack examples', () => {
    const r = ask('how do I fix sql injection in django');
    expect(r.answers[0]?.topic).toBe('sql-injection');
    expect(r.stacks).toContain('django');
    expect(r.answers[0]?.examples.some((e) => e.stack === 'django' || e.stack === 'python')).toBe(
      true,
    );
  });
  it('understands abbreviations', () => {
    expect(ask('prevent csrf').answers[0]?.topic).toBe('csrf-token-missing');
    expect(ask('ssrf').answers[0]?.topic).toBe('ssrf');
  });
  it('returns nothing for unrelated questions', () => {
    expect(ask('what is the best pizza topping').answers).toHaveLength(0);
  });
});
