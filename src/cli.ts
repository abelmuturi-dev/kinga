#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { BRAND } from './brand.js';
import { askCommand, explainCommand, topicsCommand } from './commands/explain.js';
import {
  baselineCommand,
  codeCommand,
  initCommand,
  scanCommand,
  webCommand,
} from './commands/scan.js';
import { createDefaultContext, type Context } from './context.js';
import { UsageError, UserError } from './errors.js';
import { helpTopics, mainHelp, topicHelp } from './help.js';
import { suggest } from './util/suggest.js';

type Handler = (args: string[], ctx: Context) => Promise<number>;

const COMMANDS: Record<string, Handler> = {
  scan: scanCommand,
  web: webCommand,
  code: codeCommand,
  ask: askCommand,
  explain: explainCommand,
  topics: topicsCommand,
  baseline: baselineCommand,
  init: initCommand,
};

/** Runs the CLI and returns the process exit code. Never calls process.exit itself. */
export async function run(argv: string[], ctx: Context): Promise<number> {
  const [first, ...rest] = argv;
  try {
    if (first === '--version' || first === '-V' || first === 'version') {
      ctx.print(ctx.version);
      return 0;
    }
    if (first === undefined || first === '--help' || first === '-h') {
      ctx.print(mainHelp());
      return 0;
    }
    if (first === 'help') {
      const topic = rest[0];
      if (!topic) {
        ctx.print(mainHelp());
        return 0;
      }
      const text = topicHelp(topic);
      if (!text) {
        const hint = suggest(topic, helpTopics());
        throw new UsageError(`No help for "${topic}".${hint ? ` Did you mean "${hint}"?` : ''}`);
      }
      ctx.print(text);
      return 0;
    }
    if (rest.includes('--help') || rest.includes('-h')) {
      ctx.print(topicHelp(first) ?? mainHelp());
      return 0;
    }
    const handler = COMMANDS[first];
    if (!handler) {
      const hint = suggest(first, Object.keys(COMMANDS));
      throw new UsageError(
        `Unknown command "${first}".${hint ? ` Did you mean "${hint}"?` : ''} Run \`${BRAND.command} help\`.`,
      );
    }
    return await handler(rest, ctx);
  } catch (error) {
    if (error instanceof UsageError) {
      ctx.printErr(`${BRAND.command}: ${error.message}`);
      return 2;
    }
    if (error instanceof UserError) {
      ctx.printErr(`${BRAND.command}: ${error.message}`);
      return 1;
    }
    ctx.printErr(
      `${BRAND.command}: unexpected error: ${error instanceof Error ? error.message : String(error)}`,
    );
    if (ctx.env['KINGA_DEBUG'] && error instanceof Error && error.stack) ctx.printErr(error.stack);
    else ctx.printErr('Set KINGA_DEBUG=1 for details.');
    return 1;
  }
}

function isMain(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isMain()) {
  for (const stream of [process.stdout, process.stderr]) {
    stream.on('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'EPIPE') process.exit(0);
      throw error;
    });
  }
  process.exitCode = await run(process.argv.slice(2), createDefaultContext());
}
