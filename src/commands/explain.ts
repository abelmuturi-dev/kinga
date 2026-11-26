import type { Context } from '../context.js';
import { UsageError } from '../errors.js';
import { ask, getTopic, listTopics } from '../engine/ask.js';
import type { CodeExample } from '../core/types.js';
import { parseFlags } from './flags.js';

function indent(text: string, pad: string): string {
  return text
    .split('\n')
    .map((l) => (l === '' ? '' : pad + l))
    .join('\n');
}

function printAnswer(
  ctx: Context,
  a: {
    topic: string;
    summary: string;
    why: string;
    steps: string[];
    examples: CodeExample[];
    verify: string;
    references: string[];
    cwe: string[];
  },
): void {
  const s = ctx.style;
  ctx.print(s.bold(a.topic) + (a.cwe.length ? s.dim(`  (${a.cwe.join(', ')})`) : ''));
  ctx.print(`  ${s.green('Fix:')} ${a.summary}`);
  ctx.print(`  ${a.why}`);
  if (a.steps.length > 0) {
    ctx.print('  Steps:');
    a.steps.forEach((step, i) => ctx.print(`    ${i + 1}. ${step}`));
  }
  for (const e of a.examples) {
    ctx.print(`  Example (${e.label}):`);
    ctx.print(indent(e.code, '      | '));
  }
  ctx.print(`  Verify: ${a.verify}`);
  for (const r of a.references) ctx.print(s.dim(`  ${r}`));
}

/** `kinga explain <topic>` prints one topic; `kinga ask "<question>"` finds the best match. */
export async function explainCommand(args: string[], ctx: Context): Promise<number> {
  const { positionals } = parseFlags(args, {});
  const query = positionals.join(' ').trim();
  if (query === '')
    throw new UsageError(
      'Usage: kinga explain <topic>   (see `kinga topics`)   or   kinga ask "how do I fix SQL injection in Django?"',
    );
  const direct = getTopic(query.toLowerCase());
  if (direct) {
    printAnswer(ctx, { topic: query.toLowerCase(), ...direct });
    return 0;
  }
  return askCommand(args, ctx);
}

export async function askCommand(args: string[], ctx: Context): Promise<number> {
  const { positionals } = parseFlags(args, {});
  const question = positionals.join(' ').trim();
  if (question === '')
    throw new UsageError('Usage: kinga ask "how do I fix SQL injection in Django?"');
  const result = ask(question);
  if (result.answers.length === 0) {
    ctx.print(
      'No matching guidance in the built-in knowledge base. Run `kinga topics` to see what it covers.',
    );
    return 1;
  }
  if (result.stacks.length > 0)
    ctx.print(ctx.style.dim(`Tailoring examples for: ${result.stacks.join(', ')}`));
  result.answers.forEach((a, i) => {
    if (i > 0) ctx.print('');
    printAnswer(ctx, a);
  });
  ctx.print('');
  ctx.print(
    ctx.style.dim('Answered offline from the built-in knowledge base (no external AI service).'),
  );
  return 0;
}

export async function topicsCommand(args: string[], ctx: Context): Promise<number> {
  parseFlags(args, {}, false);
  for (const t of listTopics())
    ctx.print(`${t.key.padEnd(28)} ${t.cwe.join(',').padEnd(18)} ${t.summary}`);
  return 0;
}
