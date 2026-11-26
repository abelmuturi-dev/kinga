import { describe, expect, it } from 'vitest';
import { evaluateBenchmark } from '../src/benchmark/metrics.js';
import { runRuleFixtureBenchmark, RULE_FIXTURES } from '../src/benchmark/fixtures.js';
import { CODE_RULES } from '../src/scanners/code/rules.js';

describe('benchmark metrics', () => {
  it('calculates precision, recall and F1 from expected and actual rule IDs', () => {
    const result = evaluateBenchmark(
      [
        { id: 'vulnerable', expectedRules: ['SQLI'], actualRules: ['SQLI', 'XSS'] },
        { id: 'secure', expectedRules: [], actualRules: [] },
        { id: 'missed', expectedRules: ['XSS'], actualRules: [] },
      ],
      ['SQLI', 'XSS'],
    );
    expect(result.truePositives).toBe(1);
    expect(result.falsePositives).toBe(1);
    expect(result.falseNegatives).toBe(1);
    expect(result.trueNegatives).toBe(3);
    expect(result.precision).toBe(0.5);
    expect(result.recall).toBe(0.5);
    expect(result.f1).toBe(0.5);
  });

  it('rejects duplicate fixture IDs', () => {
    expect(() =>
      evaluateBenchmark([
        { id: 'same', expectedRules: [], actualRules: [] },
        { id: 'same', expectedRules: [], actualRules: [] },
      ]),
    ).toThrow(/Duplicate/);
  });

  it('runs positive and negative fixtures against the real Kinga regex rule set', () => {
    const cases = runRuleFixtureBenchmark();
    const metrics = evaluateBenchmark(
      cases,
      CODE_RULES.map((rule) => rule.id),
    );
    expect(cases).toHaveLength(RULE_FIXTURES.length);
    expect(metrics.falsePositives).toBe(0);
    expect(metrics.falseNegatives).toBe(0);
    expect(metrics.precision).toBe(1);
    expect(metrics.recall).toBe(1);
  });
});
