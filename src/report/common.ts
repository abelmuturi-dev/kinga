import type { Finding, ScanResult, Severity } from '../core/types.js';
import { SEVERITIES, SEVERITY_RANK } from '../core/types.js';

export type ReportFormat = 'text' | 'json' | 'markdown' | 'html' | 'sarif';
export const REPORT_FORMATS: readonly ReportFormat[] = [
  'text',
  'json',
  'markdown',
  'html',
  'sarif',
];

export function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

export function meetsThreshold(findings: readonly Finding[], threshold: Severity): boolean {
  const limit = SEVERITY_RANK[threshold];
  return findings.some((f) => SEVERITY_RANK[f.severity] <= limit);
}

export function where(f: Finding): string {
  if (f.target === '') return '(project)';
  return f.line ? `${f.target}:${f.line}` : f.target;
}

export function summaryLine(result: ScanResult): string {
  const c = countBySeverity(result.findings);
  return SEVERITIES.map((s) => `${c[s]} ${s}`).join(', ');
}

/** A single 0-100 posture number: 100 is clean. Intended for trend tracking, not as a certification. */
export function postureScore(findings: readonly Finding[]): number {
  let penalty = 0;
  const weight: Record<Severity, number> = { critical: 25, high: 12, medium: 5, low: 1.5, info: 0 };
  for (const f of findings) penalty += weight[f.severity] * (f.confidence === 'low' ? 0.5 : 1);
  return Math.max(0, Math.round(100 - Math.min(100, penalty)));
}

export function grade(score: number): string {
  return score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 65 ? 'C' : score >= 50 ? 'D' : 'F';
}

export function targetLabel(t: ScanResult['targets'][number]): string {
  return t.kind === 'web' ? `${t.url} (${t.level})` : t.path;
}
