import type { ScanResult } from '../core/types.js';
import { grade, postureScore, summaryLine, targetLabel, where } from './common.js';

function fence(language: string, code: string): string[] {
  const ticks = code.includes('```') ? '````' : '```';
  return [`${ticks}${language}`, code, ticks];
}

export function renderMarkdown(result: ScanResult): string {
  const score = postureScore(result.findings);
  const out: string[] = [`# ${result.tool.name} security report`, ''];
  out.push(
    `- **Targets:** ${result.targets
      .map(targetLabel)
      .map((t) => `\`${t}\``)
      .join(', ')}`,
  );
  out.push(`- **Findings:** ${result.findings.length} (${summaryLine(result)})`);
  out.push(
    `- **Posture:** ${score}/100, grade ${grade(score)} (a trend indicator, not a certification)`,
  );
  if (result.stack.detected.length > 0)
    out.push(`- **Detected stack:** ${result.stack.detected.map((d) => d.label).join(', ')}`);
  out.push(`- **Generated:** ${result.startedAt}`);

  if (result.insights.length > 0) {
    out.push('', '## What matters most', '');
    for (const i of result.insights) {
      out.push(
        `### ${i.title} (${i.severity})`,
        '',
        i.narrative,
        '',
        `**Do this:** ${i.recommendation}`,
        '',
        `Related findings: ${i.findingIds.map((id) => `\`${id}\``).join(', ')}`,
        '',
      );
    }
  }
  if (result.fixPlan.length > 0) {
    out.push(
      '',
      '## Fix plan',
      '',
      'Ordered by value: serious and quick to fix first.',
      '',
      '| # | Severity | Action | Effort | Findings |',
      '|---|---|---|---|---|',
    );
    for (const s of result.fixPlan)
      out.push(
        `| ${s.order} | ${s.severity} | ${s.title.replace(/\|/g, '\\|')} | ${s.effort} | ${s.findingIds.length} |`,
      );
  }
  if (result.fixBundles.length > 0) {
    out.push('', '## Ready-to-paste fixes', '');
    for (const b of result.fixBundles) {
      out.push(
        `### ${b.title}`,
        '',
        `Where: ${b.location} · resolves ${b.covers.length} finding(s)`,
        '',
        ...fence(b.language, b.code),
        '',
        `_${b.note}_`,
        '',
      );
    }
  }
  out.push('', '## Findings', '');
  if (result.findings.length === 0) out.push('No findings from the checks that ran.');
  for (const f of result.findings) {
    out.push(`### ${f.id}: ${f.title}`, '');
    out.push(
      `- **Severity:** ${f.severity} · **Risk:** ${f.risk}/100 · **Certainty:** ${f.confidence} (${f.verified ? 'observed fact' : 'pattern match'})`,
    );
    out.push(`- **Where:** \`${where(f)}\``);
    out.push(`- **Evidence:** ${f.evidence.replace(/`/g, "'")}`);
    if (f.cwe.length + f.owasp.length > 0)
      out.push(`- **Standards:** ${[...f.cwe, ...f.owasp].join(', ')}`);
    out.push('', `**Fix:** ${f.advice.summary}`, '', f.advice.why, '');
    if (f.advice.steps.length > 0) out.push(...f.advice.steps.map((s, i) => `${i + 1}. ${s}`), '');
    for (const e of f.advice.examples)
      out.push(`_${e.label}_`, '', ...fence(e.language, e.code), '');
    out.push(`**Verify:** ${f.advice.verify}`, '');
    if (f.advice.references.length > 0)
      out.push(`References: ${f.advice.references.map((r) => `<${r}>`).join(' · ')}`, '');
    out.push(`<sub>How this was checked: ${f.verification}</sub>`, '');
  }
  out.push('## Not assessed', '', ...result.notAssessed.map((n) => `- ${n}`));
  return out.join('\n');
}
