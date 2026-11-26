import { watch as watchDirectory } from 'node:fs';
import path from 'node:path';
import type { Context } from '../context.js';
import { UserError } from '../errors.js';
import { runScanCommand } from './scan.js';

const IGNORED = /(^|[\\/])(?:\.git|node_modules|dist|\.kinga)(?:[\\/]|$)/;

/** Watch a project and rerun the normal, read-only code scanner after file changes. */
export async function watchCommand(args: string[], ctx: Context): Promise<number> {
  if (args.length > 1) throw new UserError('Usage: kinga watch [project-directory]');
  const root = path.resolve(ctx.cwd, args[0] ?? '.');
  const initial = await runScanCommand([root], ctx, 'code');
  ctx.print('Watching for changes. Press Ctrl+C to stop.');

  return await new Promise<number>((resolve, reject) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    let running = false;
    let pending = false;
    let closed = false;
    const watcher = (() => {
      try {
        return watchDirectory(root, { recursive: true }, (_event, filename) => {
          const name = filename?.toString() ?? '';
          if (name && IGNORED.test(name)) return;
          pending = true;
          if (timer) clearTimeout(timer);
          timer = setTimeout(() => void rescan(), 400);
        });
      } catch (error) {
        reject(
          new UserError(
            `Could not watch ${root}: ${error instanceof Error ? error.message : String(error)}. Use a Node.js runtime with recursive fs.watch support.`,
          ),
        );
        return null;
      }
    })();
    if (!watcher) return;

    const cleanup = (): void => {
      if (closed) return;
      closed = true;
      if (timer) clearTimeout(timer);
      watcher.close();
      process.removeListener('SIGINT', stop);
    };
    const stop = (): void => {
      cleanup();
      ctx.print('Watch stopped.');
      resolve(0);
    };
    const rescan = async (): Promise<void> => {
      if (closed) return;
      if (running) {
        pending = true;
        return;
      }
      running = true;
      pending = false;
      try {
        ctx.print(ctx.style.dim('Change detected; rescanning...'));
        await runScanCommand([root], ctx, 'code');
      } catch (error) {
        ctx.printErr(`Kinga watch: ${error instanceof Error ? error.message : String(error)}`);
      } finally {
        running = false;
        if (pending && !closed) void rescan();
      }
    };
    process.once('SIGINT', stop);
  }).then(() => initial);
}
