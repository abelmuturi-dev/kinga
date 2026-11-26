import { runCommand, type Runner } from './platform/exec.js';
import { redact } from './security/redact.js';
import { createStyler, shouldUseColor, type Styler } from './ui/ansi.js';
import { getVersion } from './version.js';

/** Everything a command needs from its environment. Tests substitute fakes for any field. */
export interface Context {
  version: string;
  cwd: string;
  env: NodeJS.ProcessEnv;
  stdoutIsTTY: boolean;
  style: Styler;
  run: Runner;
  sleep: (ms: number) => Promise<void>;
  /** Writes a line to stdout (secret redaction applied). */
  print(line?: string): void;
  /** Writes a line to stderr. */
  printErr(line: string): void;
}

export function createDefaultContext(): Context {
  const stdoutIsTTY = Boolean(process.stdout.isTTY);
  return {
    version: getVersion(),
    cwd: process.cwd(),
    env: process.env,
    stdoutIsTTY,
    style: createStyler(shouldUseColor(process.env, stdoutIsTTY)),
    run: runCommand,
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    print: (line = '') => {
      process.stdout.write(`${redact(line)}\n`);
    },
    printErr: (line) => {
      process.stderr.write(`${redact(line)}\n`);
    },
  };
}
