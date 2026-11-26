import { runCommand } from '../../src/platform/exec.js';
import { createStyler } from '../../src/ui/ansi.js';
import type { Context } from '../../src/context.js';

export function fakeContext(cwd: string): { ctx: Context; out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  const ctx: Context = {
    version: '9.9.9',
    cwd,
    env: { PATH: process.env['PATH'] ?? '' },
    stdoutIsTTY: false,
    style: createStyler(false),
    run: runCommand,
    sleep: async () => undefined,
    print: (line = '') => void out.push(line),
    printErr: (line) => void err.push(line),
  };
  return { ctx, out, err };
}
