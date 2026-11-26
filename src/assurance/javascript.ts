export interface JavaScriptIndicator {
  kind: 'possible-api-key' | 'possible-cloud-key' | 'source-map-reference';
  line: number;
  evidence: string;
}
/** Bounded, non-executing inspection. Secret-like values are never returned. */
export function inspectJavaScriptAsset(source: string): JavaScriptIndicator[] {
  const lines = source.slice(0, 1_000_000).split(/\r?\n/);
  const patterns: Array<[JavaScriptIndicator['kind'], RegExp]> = [
    ['possible-api-key', /\b(?:api[_-]?key|access[_-]?token|secret)\s*[:=]\s*['"][A-Za-z0-9_./+=-]{16,}['"]/i],
    ['possible-cloud-key', /\bAKIA[0-9A-Z]{16}\b/],
    ['source-map-reference', /sourceMappingURL\s*=\s*[^\s*]+/],
  ];
  const result: JavaScriptIndicator[] = [];
  lines.forEach((line, index) => {
    for (const [kind, pattern] of patterns) if (pattern.test(line)) {
      result.push({ kind, line: index + 1, evidence: 'Potential sensitive value or source-map reference; content redacted.' });
    }
  });
  return result;
}
