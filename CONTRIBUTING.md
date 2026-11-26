# Contributing

```bash
npm install
npm run check      # format check, lint, typecheck, tests
npm run build
```

## Adding a detection rule

1. Code rule: add an entry to `CODE_RULES` in `src/scanners/code/rules.ts` (pattern, `appliesTo`,
   optional `accept` to drop false positives). Web checks live in `src/scanners/web/checks/`.
2. Point it at a knowledge-base topic with `kb:`. Add the topic in `src/engine/kb/*.ts` if it is new:
   summary, why, steps, stack-specific examples, how to verify, references, CWE and OWASP ids.
3. Add true-positive **and** false-positive cases to `tests/rules.test.ts`.
4. `tests/kb-coverage.test.ts` fails if a rule uses a missing topic or a topic has no rule.

Precision matters more than recall: a noisy rule trains people to ignore the tool. Prefer
`confidence: 'low'` and a clear `verification` note for pattern-only matches.
