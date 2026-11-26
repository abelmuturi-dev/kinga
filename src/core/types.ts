export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export type Confidence = 'high' | 'medium' | 'low';

/** Which scanner produced a finding. */
export type Domain = 'web' | 'code' | 'deps' | 'config' | 'secrets';
export const DOMAINS: readonly Domain[] = ['web', 'code', 'deps', 'config', 'secrets'];

export type Effort = 'minutes' | 'hours' | 'days';

/** Technology a fix example is written for. `generic` is the fallback. */
export type StackKey =
  | 'generic'
  | 'nginx'
  | 'apache'
  | 'caddy'
  | 'iis'
  | 'node'
  | 'express'
  | 'nextjs'
  | 'python'
  | 'django'
  | 'flask'
  | 'fastapi'
  | 'java'
  | 'spring'
  | 'php'
  | 'laravel'
  | 'wordpress'
  | 'ruby'
  | 'rails'
  | 'dotnet'
  | 'go'
  | 'docker'
  | 'kubernetes'
  | 'terraform'
  | 'github-actions';

export interface CodeExample {
  label: string;
  /** Syntax highlighting hint, also used as the fenced-block language in Markdown. */
  language: string;
  code: string;
  stack: StackKey;
}

/** The "what to do about it" part of a finding, produced by the built-in engine. */
export interface Advice {
  summary: string;
  why: string;
  steps: string[];
  examples: CodeExample[];
  verify: string;
  references: string[];
  effort: Effort;
}

/** What a scanner emits. The engine adds ids, standards mapping, risk score and advice. */
export interface RawFinding {
  /** Rule id, for example `WEB-HDR-001` or `CODE-INJ-003`. */
  rule: string;
  /** Knowledge-base topic that explains and fixes this kind of problem. */
  kb: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  domain: Domain;
  category: string;
  /** URL for web findings, project-relative path for code findings, empty for project-level. */
  target: string;
  line?: number;
  /** What was actually observed. Secret values are never included. */
  evidence: string;
  /** True only for directly observed facts (a header that is absent, a file that is served). */
  verified: boolean;
  verification: string;
  tags?: string[];
  /** Extra structured facts other engine stages can use (never shown verbatim). */
  facts?: Record<string, string | number | boolean>;
}

export interface Finding extends RawFinding {
  id: string;
  cwe: string[];
  owasp: string[];
  /** 0-100, higher means fix sooner. Combines severity, confidence, exposure and context. */
  risk: number;
  advice: Advice;
  /** Stable across runs for the same problem in the same place; used by baselines. */
  fingerprint: string;
}

export interface Insight {
  id: string;
  title: string;
  severity: Severity;
  /** Plain-language explanation of how findings combine into a larger problem. */
  narrative: string;
  findingIds: string[];
  recommendation: string;
}

export interface FixStep {
  order: number;
  title: string;
  why: string;
  effort: Effort;
  findingIds: string[];
  /** Highest severity among the findings this step resolves. */
  severity: Severity;
}

/** A ready-to-paste change that resolves several findings at once. */
export interface FixBundle {
  title: string;
  stack: StackKey;
  language: string;
  /** Where to put it, for example `nginx.conf (server block)`. */
  location: string;
  code: string;
  covers: string[];
  note: string;
}

export interface StackInfo {
  /** Technologies detected, each with the evidence that suggested it. */
  detected: Array<{ stack: StackKey; label: string; evidence: string }>;
}

export type TargetSummary =
  | {
      kind: 'web';
      url: string;
      level: 'passive' | 'active';
      requests: number;
      pagesAnalysed: number;
      reachable: boolean;
      notes: string[];
    }
  | {
      kind: 'project';
      path: string;
      filesScanned: number;
      filesSkipped: number;
      manifests: string[];
      truncated: boolean;
      suppressed: number;
      notes: string[];
    };

export interface ScanResult {
  tool: { name: string; version: string };
  startedAt: string;
  durationMs: number;
  targets: TargetSummary[];
  findings: Finding[];
  insights: Insight[];
  fixPlan: FixStep[];
  fixBundles: FixBundle[];
  stack: StackInfo;
  /** Findings removed by a baseline file. */
  baselined: number;
  notAssessed: string[];
}

export interface Rule {
  id: string;
  title: string;
  domain: Domain;
  severity: Severity;
}

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function isSeverity(value: string): value is Severity {
  return (SEVERITIES as readonly string[]).includes(value);
}
