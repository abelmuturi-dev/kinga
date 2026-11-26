export interface RemediationPreview {
  rule: string;
  path: string;
  line: number;
  safe: true;
  explanation: string;
  patch: string;
}

/**
 * Produce a review-only patch for a narrow, mechanical fix.
 * This module never writes to the user's source tree or applies a patch.
 */
export function previewSafeRemediation(
  rule: string,
  filePath: string,
  source: string,
  lineNumber: number,
): RemediationPreview | null {
  if (rule !== 'CODE-WEB-002' || !Number.isInteger(lineNumber) || lineNumber < 1) {
    return null;
  }
  const lines = source.split(/\r?\n/);
  const index = lineNumber - 1;
  const original = lines[index];
  if (original === undefined || original.length > 4000) return null;

  const anchor = /<a\b[^>]*\btarget\s*=\s*(["'])_blank\1[^>]*>/i;
  const match = anchor.exec(original);
  if (!match || /\brel\s*=\s*(["'])[^"']*\bnoopener\b[^"']*\1/i.test(match[0])) {
    return null;
  }

  const tag = match[0];
  const rel = /\brel\s*=\s*(["'])(.*?)\1/i.exec(tag);
  let replacement: string;
  if (rel) {
    const updated = [...new Set(rel[2]!.split(/\s+/).filter(Boolean).concat('noopener'))].join(' ');
    replacement = tag.replace(rel[0], `rel=${rel[1]}${updated}${rel[1]}`);
  } else {
    replacement = tag.endsWith('/>')
      ? tag.replace(/\s*\/>$/, ' rel="noopener noreferrer"/>')
      : tag.replace(/>$/, ' rel="noopener noreferrer">');
  }
  const updatedLine = original.replace(tag, replacement);
  if (updatedLine === original) return null;

  return {
    rule,
    path: filePath,
    line: lineNumber,
    safe: true,
    explanation:
      'Adds the noopener relationship to a target=_blank link to prevent the opened page from controlling the opener window. Review the diff before applying.',
    patch: [
      `--- a/${filePath}`,
      `+++ b/${filePath}`,
      `@@ -${lineNumber},1 +${lineNumber},1 @@`,
      `-${original}`,
      `+${updatedLine}`,
    ].join('\n'),
  };
}
