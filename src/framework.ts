import { promises as fs } from 'node:fs';
import path from 'node:path';
import { loadBaseline, pathIgnored, type KingaConfig, EMPTY_CONFIG } from './core/config.js';
import type { Finding, RawFinding, ScanResult, TargetSummary } from './core/types.js';
import { SEVERITY_RANK } from './core/types.js';
import { toFinding } from './engine/advisor.js';
import { buildBundles } from './engine/bundles.js';
import { buildFixPlan, deriveInsights } from './engine/insights.js';
import { detectProjectStack, detectWebStack, mergeStacks } from './engine/stack.js';
import { UserError } from './errors.js';
import type { Runner } from './platform/exec.js';
import { AdvisoryDb, loadAdvisoryFile } from './scanners/deps/advisories.js';
import { DEFAULT_CODE_OPTIONS, runCodeScan } from './scanners/code/scan.js';
import { DEFAULT_WEB_OPTIONS, runWebScan, type WebScanOptions } from './scanners/web/scan.js';
import { BRAND } from './brand.js';
import type { WebContext } from './scanners/web/context.js';

export interface ScanRequest {
  /** URLs or hosts to scan as a live website. */
  webTargets: string[];
  /** Project directories to scan as code. */
  projectPaths: string[];
  web: Partial<
    Pick<
      WebScanOptions,
      | 'level'
      | 'authorized'
      | 'timeoutMs'
      | 'delayMs'
      | 'maxRequests'
      | 'maxPages'
      | 'insecure'
      | 'auth'
    >
  >;
  config: KingaConfig;
  version: string;
  run: Runner;
  env: NodeJS.ProcessEnv;
  sleep: (ms: number) => Promise<void>;
  now?: Date;
  /** Ignore the baseline file for this run. */
  noBaseline?: boolean;
}

export const NOT_ASSESSED: readonly string[] = [
  'Business-logic flaws and broken access control between users (needs an understanding of what each user may do)',
  'Multi-step login and identity-provider flows (web scans support only explicit, exact-origin Authorization or Cookie headers)',
  'Interprocedural and path-sensitive data flow (the AST taint pass is conservative and intraprocedural)',
  'Vulnerabilities in dependency versions that are not in the bundled advisory snapshot (run npm audit / pip-audit / OSV-Scanner too)',
  'Network-level exposure, firewall rules and cloud account configuration (only IaC files are read)',
  'Denial-of-service resilience, race conditions and cryptographic protocol implementation bugs',
];

export async function scan(request: ScanRequest): Promise<ScanResult> {
  const started = Date.now();
  if (request.webTargets.length === 0 && request.projectPaths.length === 0)
    throw new UserError(
      'Nothing to scan: give a URL (web scan) and/or a project directory (code scan).',
    );

  const { config } = request;
  const db = new AdvisoryDb();
  if (config.advisoriesFile) {
    try {
      for (const a of await loadAdvisoryFile(config.advisoriesFile)) db.add(a);
    } catch (error) {
      throw new UserError(error instanceof Error ? error.message : String(error));
    }
  }

  const raws: RawFinding[] = [];
  const targets: TargetSummary[] = [];
  const stackLists: ReturnType<typeof detectWebStack>[] = [];
  const webContexts: WebContext[] = [];

  for (const input of request.webTargets) {
    const out = await runWebScan(input, {
      ...DEFAULT_WEB_OPTIONS,
      ...request.web,
      version: request.version,
      sleep: request.sleep,
      ...(request.now ? { now: request.now } : {}),
    });
    raws.push(
      ...out.findings.map((f) =>
        out.context.local ? { ...f, facts: { ...f.facts, local: true } } : f,
      ),
    );
    targets.push(out.summary);
    webContexts.push(out.context);
    stackLists.push(detectWebStack(out.context));
  }

  for (const dir of request.projectPaths) {
    const resolved = path.resolve(dir);
    const stat = await fs.stat(resolved).catch(() => null);
    if (!stat?.isDirectory()) throw new UserError(`"${dir}" is not a directory.`);
    const out = await runCodeScan(resolved, request.run, request.env, {
      ...DEFAULT_CODE_OPTIONS,
      advisories: db,
      extraRules: config.customRules,
    });
    raws.push(...out.findings);
    targets.push(out.summary);
    stackLists.push(detectProjectStack(out.index));
  }

  const stack = mergeStacks(...stackLists);
  const stackKeys = stack.detected.map((d) => d.stack);

  // Suppressions: rules, paths, baseline.
  let baselined = 0;
  const baseline =
    !request.noBaseline && config.baseline
      ? await loadBaseline(config.baseline)
      : new Set<string>();
  const kept: RawFinding[] = [];
  const probe = (r: RawFinding): Finding => toFinding(r, 'tmp', stackKeys);
  for (const r of raws) {
    if (config.ignoreRules.includes(r.rule)) continue;
    if (r.domain !== 'web' && pathIgnored(config, r.target)) continue;
    if (baseline.size > 0 && baseline.has(probe(r).fingerprint)) {
      baselined++;
      continue;
    }
    kept.push(r);
  }

  // Number findings per rule after a stable sort, then advise.
  kept.sort(
    (a, b) =>
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
      a.target.localeCompare(b.target) ||
      (a.line ?? 0) - (b.line ?? 0) ||
      a.rule.localeCompare(b.rule),
  );
  const counters = new Map<string, number>();
  const findings = kept.map((r) => {
    const n = (counters.get(r.rule) ?? 0) + 1;
    counters.set(r.rule, n);
    return toFinding(r, `${r.rule}#${n}`, stackKeys);
  });
  findings.sort((a, b) => b.risk - a.risk || SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);

  const https = webContexts.some((c) => c.target.protocol === 'https:') || webContexts.length === 0;
  return {
    tool: { name: BRAND.name, version: request.version },
    startedAt: new Date(started).toISOString(),
    durationMs: Date.now() - started,
    targets,
    findings,
    insights: deriveInsights(findings),
    fixPlan: buildFixPlan(findings),
    fixBundles: buildBundles(findings, stackKeys, https),
    stack,
    baselined,
    notAssessed: [...NOT_ASSESSED],
  };
}

export { EMPTY_CONFIG };
