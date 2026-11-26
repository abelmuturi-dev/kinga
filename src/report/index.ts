import type { ScanResult, Severity } from '../core/types.js';
import { redactTokens } from '../security/redact.js';
import type { Styler } from '../ui/ansi.js';
import { countBySeverity, postureScore, type ReportFormat } from './common.js';
import { renderHtml } from './html.js';
import { renderMarkdown } from './markdown.js';
import { renderSarif } from './sarif.js';
import { renderText } from './text.js';

export { countBySeverity, meetsThreshold, REPORT_FORMATS, type ReportFormat } from './common.js';

export interface RenderOptions {
  style: Styler;
  verbose: boolean;
  minSeverity: Severity;
}

/** Renders a report. The result passes through secret redaction as a last line of defence. */
export function renderReport(
  result: ScanResult,
  format: ReportFormat,
  options: RenderOptions,
): string {
  let body: string;
  switch (format) {
    case 'json':
      body = JSON.stringify(
        {
          ...result,
          summary: countBySeverity(result.findings),
          posture: postureScore(result.findings),
        },
        null,
        2,
      );
      break;
    case 'markdown':
      body = renderMarkdown(result);
      break;
    case 'html':
      body = renderHtml(result);
      break;
    case 'sarif':
      body = renderSarif(result);
      break;
    default:
      body = renderText(result, options.style, {
        verbose: options.verbose,
        minSeverity: options.minSeverity,
      });
  }
  return redactTokens(body);
}
