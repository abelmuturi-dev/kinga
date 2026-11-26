import type { Finding, ScanResult, Severity } from '../core/types.js';
import { SEVERITIES } from '../core/types.js';
import type { Styler } from '../ui/ansi.js';
import { grade, postureScore, summaryLine, targetLabel, where } from './common.js';

export interface TextOptions {
  /** Show full guidance for every finding (default shows it for medium and above). */
  verbose: boolean;
  /** Minimum severity shown in the finding list. */
  minSeverity: Severity;
}

function paint(style: Styler, sev: Severity, text: string): string {
  switch (sev) {
    case 'critical':
    case 'high':
      return style.red(text);
    case 'medium':
      return style.yellow(text);
    case 'low':
      return style.cyan(text);
    default:
      return style.dim(text);
  }
}

function indent(text: string, pad: string): string {
  return text
    .split('\n')
    .map((l) => (l === '' ? '' : pad + l))
    .join('\n');
}

export function renderText(result: ScanResult, style: Styler, options: TextOptions): string {
  const out: string[] = [];
  const score = postureScore(result.findings);
  const limit = SEVERITIES.indexOf(options.minSeverity);
  const shown = result.findings.filter((f) => SEVERITIES.indexOf(f.severity) <= limit);

  out.push(
    style.bold(`${result.tool.name} security report`) + style.dim(`  v${result.tool.version}`),
  );
  for (const t of result.targets) out.push(`  Target:   ${targetLabel(t)}`);
  out.push(`  Findings: ${result.findings.length} (${summaryLine(result)})`);
  out.push(
    `  Posture:  ${score}/100 (grade ${grade(score)})  ${style.dim('trend indicator, not a certification')}`,
  );
  if (result.stack.detected.length > 0)
    out.push(
      `  Stack:    ${result.stack.detected.map((d) => d.label).join(', ')}  ${style.dim('(fixes are tailored to this)')}`,
    );
  if (result.baselined > 0)
    out.push(`  ${result.baselined} known finding(s) hidden by the baseline.`);
  for (const t of result.targets) {
    if (t.kind === 'web') {
      out.push(
        style.dim(
          `  Web scan: ${t.requests} request(s), ${t.pagesAnalysed} page(s)${t.reachable ? '' : ', target unreachable'}`,
        ),
      );
      for (const n of t.notes) out.push(style.dim(`    note: ${n}`));
    } else {
      out.push(
        style.dim(
          `  Code scan: ${t.filesScanned} file(s) scanned, ${t.filesSkipped} skipped${t.truncated ? ', file list truncated' : ''}${t.suppressed ? `, ${t.suppressed} line(s) suppressed` : ''}`,
        ),
      );
      for (const n of t.notes) out.push(style.dim(`    note: ${n}`));
    }
  }

  if (result.insights.length > 0) {
    out.push('', style.bold('What matters most'));
    for (const i of result.insights) {
      out.push(
        `  ${paint(style, i.severity, `[${i.severity.toUpperCase()}]`)} ${style.bold(i.title)}`,
      );
      out.push(indent(i.narrative, '      '));
      out.push(`      ${style.green('Do this:')} ${i.recommendation}`);
    }
  }

  if (result.fixPlan.length > 0) {
    out.push('', style.bold('Fix plan (most valuable first)'));
    for (const step of result.fixPlan.slice(0, 12)) {
      out.push(
        `  ${String(step.order).padStart(2)}. ${paint(style, step.severity, step.severity.padEnd(8))} ${step.title} ${style.dim(`(${step.effort}, ${step.findingIds.length} finding${step.findingIds.length === 1 ? '' : 's'})`)}`,
      );
    }
    if (result.fixPlan.length > 12)
      out.push(
        style.dim(
          `      … and ${result.fixPlan.length - 12} more steps (use --format markdown or html for all).`,
        ),
      );
  }

  if (result.fixBundles.length > 0) {
    out.push('', style.bold('Ready-to-paste fixes'));
    for (const b of result.fixBundles) {
      out.push(
        `  ${style.bold(b.title)} ${style.dim(`→ ${b.location}; resolves ${b.covers.length} finding(s)`)}`,
      );
      out.push(indent(b.code, '      | '));
      out.push(`      ${style.dim(b.note)}`);
    }
  }

  out.push('', style.bold('Findings'));
  if (shown.length === 0)
    out.push(
      '  None at this level. That does not mean the system is free of problems (see "Not assessed").',
    );
  for (const f of shown) out.push('', ...renderFinding(f, style, options.verbose));

  out.push('', style.bold('Not assessed by this scan'));
  for (const n of result.notAssessed) out.push(`  - ${n}`);
  return out.join('\n');
}

function renderFinding(f: Finding, style: Styler, verbose: boolean): string[] {
  const out: string[] = [];
  const full =
    verbose || f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium';
  out.push(
    `${paint(style, f.severity, `[${f.severity.toUpperCase()}]`)} ${style.bold(f.id)} ${f.title}  ${style.dim(`risk ${f.risk}`)}`,
  );
  out.push(`  Where:    ${where(f)}`);
  out.push(`  Evidence: ${f.evidence}`);
  out.push(
    `  Certainty: ${f.confidence}${f.verified ? ' (observed fact)' : ' (pattern match, not proven)'}`,
  );
  if (f.cwe.length > 0 || f.owasp.length > 0)
    out.push(style.dim(`  Maps to:  ${[...f.cwe, ...f.owasp].join(', ')}`));
  out.push(`  ${style.green('Fix:')}      ${f.advice.summary}`);
  if (!full) return out;
  out.push(`  Why:      ${f.advice.why}`);
  if (f.advice.steps.length > 0) {
    out.push('  Steps:');
    f.advice.steps.forEach((s, i) => out.push(`    ${i + 1}. ${s}`));
  }
  for (const e of f.advice.examples.slice(0, 2)) {
    out.push(`  Example (${e.label}):`);
    out.push(indent(e.code, '      | '));
  }
  out.push(`  Verify:   ${f.advice.verify}`);
  out.push(style.dim(`  Checked:  ${f.verification}`));
  return out;
}
