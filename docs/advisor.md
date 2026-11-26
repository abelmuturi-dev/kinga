# Kinga Advisor

An offline expert system, **not a neural language model**. It has no network access and uses no API.

- **Knowledge base** (`src/engine/kb/*`): about 100 topics. Each has a summary, why it matters, steps,
  effort, CWE/OWASP ids, per-stack examples, a verification method and references.
- **Stack detection** (`stack.ts`): infers technologies from headers, cookies, manifests and files, so the
  matching example is shown first.
- **Risk score** (`advisor.ts`): severity x confidence, with bonuses for observed facts and context.
- **Insights** (`insights.ts`): rules that combine findings (INS-001..011), e.g. exposed `.env` plus hard-coded keys.
- **Fix plan and bundles** (`insights.ts`, `bundles.ts`): grouped, ordered by risk and effort; merged config snippets.
- **`kinga ask`** (`ask.ts`): keyword and synonym matching over topics. If nothing matches it says so
  instead of inventing an answer.

To extend: add a topic to the relevant `kb` file and reference it from a rule. `tests/kb-coverage.test.ts`
keeps rules and topics in sync.
