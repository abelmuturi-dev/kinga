import { promises as fs } from 'node:fs';
import path from 'node:path';
import { BRAND } from '../brand.js';
import { DEFAULT_CONFIG_TEXT, loadConfig } from '../core/config.js';
import { isSeverity, SEVERITIES, type Severity } from '../core/types.js';
import type { Context } from '../context.js';
import { UsageError, UserError } from '../errors.js';
import { scan } from '../framework.js';
import {
  meetsThreshold,
  renderReport,
  REPORT_FORMATS,
  type ReportFormat,
} from '../report/index.js';
import { flag, parseFlags, str, strs } from './flags.js';

const SCAN_FLAGS = {
  project: { type: 'string', short: 'p', multiple: true },
  url: { type: 'string', short: 'u', multiple: true },
  level: { type: 'string' },
  authorized: { type: 'boolean' },
  insecure: { type: 'boolean' },
  format: { type: 'string', short: 'f' },
  output: { type: 'string', short: 'o' },
  'fail-on': { type: 'string' },
  'min-severity': { type: 'string' },
  verbose: { type: 'boolean', short: 'v' },
  config: { type: 'string', short: 'c' },
  'no-baseline': { type: 'boolean' },
  'max-requests': { type: 'string' },
  'max-pages': { type: 'string' },
  delay: { type: 'string' },
  timeout: { type: 'string' },
} as const;

function intFlag(
  values: ReturnType<typeof parseFlags>['values'],
  name: string,
  min: number,
  max: number,
): number | undefined {
  const raw = str(values, name);
  if (raw === undefined) return undefined;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max)
    throw new UsageError(`--${name} must be an integer from ${min} to ${max}`);
  return n;
}

async function isDirectory(p: string): Promise<boolean> {
  return (await fs.stat(p).catch(() => null))?.isDirectory() ?? false;
}

const LOOKS_LIKE_URL =
  /^(https?:\/\/|localhost\b|\d{1,3}(\.\d{1,3}){3}\b|[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?(\/|$))/i;

/** Sorts bare arguments into web targets (URLs/hosts) and project directories. */
export async function classifyTargets(
  args: readonly string[],
  cwd: string,
): Promise<{ web: string[]; projects: string[] }> {
  const web: string[] = [];
  const projects: string[] = [];
  for (const arg of args) {
    const resolved = path.resolve(cwd, arg);
    if (/^https?:\/\//i.test(arg)) web.push(arg);
    else if (await isDirectory(resolved)) projects.push(resolved);
    else if (LOOKS_LIKE_URL.test(arg)) web.push(arg);
    else throw new UsageError(`"${arg}" is neither a directory nor a URL/host.`);
  }
  return { web, projects };
}

type Mode = 'auto' | 'web' | 'code';

export async function runScanCommand(args: string[], ctx: Context, mode: Mode): Promise<number> {
  const { values, positionals } = parseFlags(args, SCAN_FLAGS);
  const format = (str(values, 'format') ?? 'text') as ReportFormat;
  if (!REPORT_FORMATS.includes(format))
    throw new UsageError(`--format must be one of ${REPORT_FORMATS.join(', ')}`);
  const level = str(values, 'level') ?? 'passive';
  if (level !== 'passive' && level !== 'active')
    throw new UsageError('--level must be passive or active');
  const failOnRaw = str(values, 'fail-on');
  if (failOnRaw !== undefined && !isSeverity(failOnRaw))
    throw new UsageError(`--fail-on must be one of ${SEVERITIES.join(', ')}`);
  const minRaw = str(values, 'min-severity') ?? 'info';
  if (!isSeverity(minRaw))
    throw new UsageError(`--min-severity must be one of ${SEVERITIES.join(', ')}`);

  const classified = await classifyTargets(positionals, ctx.cwd);
  const web = [...classified.web, ...strs(values, 'url')];
  const projects = [
    ...classified.projects,
    ...strs(values, 'project').map((p) => path.resolve(ctx.cwd, p)),
  ];
  if (mode === 'web' && projects.length > 0)
    throw new UsageError(
      '`web` scans URLs only; use `kinga scan` or `kinga code` for directories.',
    );
  if (mode === 'code' && web.length > 0)
    throw new UsageError(
      '`code` scans directories only; use `kinga scan` or `kinga web` for URLs.',
    );
  if (web.length === 0 && projects.length === 0) {
    if (mode === 'web')
      throw new UsageError('Usage: kinga web <url> [--level active --authorized]');
    projects.push(ctx.cwd);
  }
  if (level === 'active' && web.length === 0)
    ctx.printErr(ctx.style.dim('Note: --level only affects web scans.'));

  const config = await loadConfig(str(values, 'config'), [ctx.cwd, ...projects]);
  const failOn: Severity | undefined = (failOnRaw as Severity | undefined) ?? config.failOn;
  const maxRequests = intFlag(values, 'max-requests', 1, 1000);
  const maxPages = intFlag(values, 'max-pages', 1, 100);
  const delayMs = intFlag(values, 'delay', 0, 10_000);
  const timeoutMs = intFlag(values, 'timeout', 500, 120_000);
  const authOriginRaw = ctx.env['KINGA_AUTH_ORIGIN'];
  const authHeaderRaw = ctx.env['KINGA_AUTH_HEADER'];
  const authValue = ctx.env['KINGA_AUTH_VALUE'];
  const authConfigured = [authOriginRaw, authHeaderRaw, authValue].some(
    (value) => value !== undefined,
  );
  let auth:
    | { origin: string; headerName: 'authorization' | 'cookie'; headerValue: string }
    | undefined;
  if (authConfigured) {
    if (!authOriginRaw || !authHeaderRaw || !authValue) {
      throw new UsageError(
        'Authenticated scanning needs KINGA_AUTH_ORIGIN, KINGA_AUTH_HEADER and KINGA_AUTH_VALUE.',
      );
    }
    let authUrl: URL;
    try {
      authUrl = new URL(authOriginRaw);
    } catch {
      throw new UsageError('KINGA_AUTH_ORIGIN must be an absolute HTTP(S) origin.');
    }
    if (
      !['http:', 'https:'].includes(authUrl.protocol) ||
      authUrl.username ||
      authUrl.password ||
      authUrl.pathname !== '/' ||
      authUrl.search ||
      authUrl.hash
    ) {
      throw new UsageError('KINGA_AUTH_ORIGIN must contain only an HTTP(S) origin.');
    }
    const headerName = authHeaderRaw.toLowerCase();
    if (headerName !== 'authorization' && headerName !== 'cookie') {
      throw new UsageError('KINGA_AUTH_HEADER must be Authorization or Cookie.');
    }
    if (/[\r\n]/.test(authValue) || authValue.length > 8192) {
      throw new UsageError('KINGA_AUTH_VALUE contains invalid characters or exceeds 8 KB.');
    }
    if (web.length === 0) {
      throw new UsageError('Authenticated scanning is available only for web targets.');
    }
    auth = {
      origin: authUrl.origin,
      headerName,
      headerValue: authValue,
    };
  }

  if (web.length > 0) {
    ctx.printErr(
      ctx.style.dim(
        level === 'active'
          ? 'Active web scan: sends a small set of extra probe requests. Only scan systems you own or are authorised to test.'
          : 'Passive web scan: normal page requests only.',
      ),
    );
  }

  const result = await scan({
    webTargets: web,
    projectPaths: projects,
    web: {
      level,
      authorized: flag(values, 'authorized'),
      insecure: flag(values, 'insecure'),
      ...(auth ? { auth } : {}),
      ...(maxRequests !== undefined ? { maxRequests } : {}),
      ...(maxPages !== undefined ? { maxPages } : {}),
      ...(delayMs !== undefined ? { delayMs } : {}),
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
    },
    config,
    version: ctx.version,
    run: ctx.run,
    env: ctx.env,
    sleep: ctx.sleep,
    noBaseline: flag(values, 'no-baseline'),
  });

  const report = renderReport(result, format, {
    style: ctx.style,
    verbose: flag(values, 'verbose'),
    minSeverity: minRaw,
  });
  const out = str(values, 'output');
  if (out !== undefined) {
    const file = path.resolve(ctx.cwd, out);
    for (const dir of projects) {
      const rel = path.relative(dir, file);
      if (rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel))
        throw new UserError(
          'Refusing to write the report inside the scanned project; choose a location outside it.',
        );
    }
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file, `${report}\n`, 'utf8');
    ctx.printErr(`Report written to ${file}`);
    if (format === 'text') ctx.print(`${result.findings.length} finding(s). Full report: ${file}`);
  } else ctx.print(report);

  return failOn && meetsThreshold(result.findings, failOn) ? 1 : 0;
}

export const scanCommand = (args: string[], ctx: Context): Promise<number> =>
  runScanCommand(args, ctx, 'auto');
export const webCommand = (args: string[], ctx: Context): Promise<number> =>
  runScanCommand(args, ctx, 'web');
export const codeCommand = (args: string[], ctx: Context): Promise<number> =>
  runScanCommand(args, ctx, 'code');

/** `kinga baseline`: record the current findings so future scans only show new ones. */
export async function baselineCommand(args: string[], ctx: Context): Promise<number> {
  const { values, positionals } = parseFlags(args, {
    config: { type: 'string', short: 'c' },
    output: { type: 'string', short: 'o' },
  });
  const { projects, web } = await classifyTargets(positionals, ctx.cwd);
  if (web.length > 0)
    throw new UsageError('Baselines are for project scans (code findings have stable locations).');
  if (projects.length === 0) projects.push(ctx.cwd);
  const config = await loadConfig(str(values, 'config'), [ctx.cwd, ...projects]);
  const result = await scan({
    webTargets: [],
    projectPaths: projects,
    web: {},
    config,
    version: ctx.version,
    run: ctx.run,
    env: ctx.env,
    sleep: ctx.sleep,
    noBaseline: true,
  });
  const file = path.resolve(
    ctx.cwd,
    str(values, 'output') ??
      config.baseline ??
      path.join(projects[0] ?? ctx.cwd, BRAND.stateDir, 'baseline.json'),
  );
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(
    file,
    `${JSON.stringify({ generated: new Date().toISOString(), tool: BRAND.name, fingerprints: result.findings.map((f) => f.fingerprint) }, null, 2)}\n`,
    'utf8',
  );
  ctx.print(`Baseline of ${result.findings.length} finding(s) written to ${file}`);
  if (!config.baseline)
    ctx.print(
      `Add  "baseline": "${path.relative(ctx.cwd, file) || file}"  to ${BRAND.configFile} so scans use it.`,
    );
  return 0;
}

export async function initCommand(args: string[], ctx: Context): Promise<number> {
  parseFlags(args, {}, false);
  const file = path.join(ctx.cwd, BRAND.configFile);
  if (
    await fs.stat(file).then(
      () => true,
      () => false,
    )
  )
    throw new UserError(`${BRAND.configFile} already exists.`);
  await fs.writeFile(file, DEFAULT_CONFIG_TEXT, 'utf8');
  ctx.print(`Created ${file}`);
  ctx.print(`Tip: add ${BRAND.stateDir}/ to .gitignore unless you want to commit the baseline.`);
  return 0;
}
