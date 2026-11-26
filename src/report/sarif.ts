import type { Finding, ScanResult, Severity } from '../core/types.js';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

/** SARIF 2.1.0, so results show up in GitHub code scanning and most security dashboards. */
export function renderSarif(result: ScanResult): string {
  const rules = new Map<string, Finding>();
  for (const f of result.findings) if (!rules.has(f.rule)) rules.set(f.rule, f);
  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: result.tool.name,
            version: result.tool.version,
            rules: [...rules.values()].map((f) => ({
              id: f.rule,
              name: f.title,
              shortDescription: { text: f.title },
              fullDescription: { text: f.advice.why },
              help: {
                text: `${f.advice.summary}\n\n${f.advice.steps.map((s, i) => `${i + 1}. ${s}`).join('\n')}`,
                markdown: `**${f.advice.summary}**\n\n${f.advice.steps.map((s, i) => `${i + 1}. ${s}`).join('\n')}`,
              },
              defaultConfiguration: { level: LEVEL[f.severity] },
              properties: {
                tags: [...f.cwe, ...f.owasp],
                'security-severity': String((f.risk / 10).toFixed(1)),
              },
            })),
          },
        },
        results: result.findings.map((f) => ({
          ruleId: f.rule,
          level: LEVEL[f.severity],
          message: { text: `${f.title}. ${f.evidence} Fix: ${f.advice.summary}` },
          partialFingerprints: { kinga: f.fingerprint },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.target === '' ? '.' : f.target },
                ...(f.line ? { region: { startLine: f.line } } : {}),
              },
            },
          ],
        })),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}
