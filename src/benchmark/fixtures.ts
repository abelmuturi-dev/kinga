import { CODE_RULES } from '../scanners/code/rules.js';
import type { BenchmarkCase } from './metrics.js';

export interface RuleFixture {
  id: string;
  file: string;
  line: string;
  expectedRules: readonly string[];
  tags: readonly string[];
}

export const RULE_FIXTURES: readonly RuleFixture[] = [
  {
    id: 'js-sql-interpolation',
    file: 'src/query.js',
    line: 'db.query(`SELECT * FROM users WHERE id = ${input}`);',
    expectedRules: ['CODE-INJ-002'],
    tags: ['javascript', 'sql-injection', 'positive'],
  },
  {
    id: 'js-sql-parameterized',
    file: 'src/query.js',
    line: "db.query('SELECT * FROM users WHERE id = $1', [input]);",
    expectedRules: [],
    tags: ['javascript', 'sql-injection', 'negative'],
  },
  {
    id: 'js-eval-input',
    file: 'src/app.js',
    line: 'eval(userInput);',
    expectedRules: ['CODE-INJ-004'],
    tags: ['javascript', 'code-injection', 'positive'],
  },
  {
    id: 'js-eval-prose',
    file: 'src/help.js',
    line: "const help = 'eval() is dangerous';",
    expectedRules: [],
    tags: ['javascript', 'code-injection', 'negative'],
  },
  {
    id: 'python-exec',
    file: 'src/app.py',
    line: 'exec(user_input)',
    expectedRules: ['CODE-INJ-007'],
    tags: ['python', 'code-injection', 'positive'],
  },
  {
    id: 'python-safe-yaml',
    file: 'src/config.py',
    line: 'data = yaml.safe_load(text)',
    expectedRules: [],
    tags: ['python', 'deserialization', 'negative'],
  },
  {
    id: 'python-unsafe-yaml',
    file: 'src/config.py',
    line: 'data = yaml.load(text)',
    expectedRules: ['CODE-DES-001'],
    tags: ['python', 'deserialization', 'positive'],
  },
  {
    id: 'js-env-secret',
    file: 'src/config.js',
    line: 'const apiKey = process.env.API_KEY;',
    expectedRules: [],
    tags: ['javascript', 'secrets', 'negative'],
  },
];

export function runRuleFixtureBenchmark(): BenchmarkCase[] {
  return RULE_FIXTURES.map((fixture) => {
    const actualRules = CODE_RULES.filter((rule) => {
      if (!rule.appliesTo(fixture.file)) return false;
      const match = new RegExp(rule.pattern.source, rule.pattern.flags.replace('g', '')).exec(
        fixture.line,
      );
      return Boolean(match && (!rule.accept || rule.accept(fixture.line, match)));
    }).map((rule) => rule.id);
    return {
      id: fixture.id,
      expectedRules: fixture.expectedRules,
      actualRules,
      tags: fixture.tags,
    };
  });
}
