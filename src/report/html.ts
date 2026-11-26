import type { Finding, ScanResult, Severity } from '../core/types.js';
import { SEVERITIES } from '../core/types.js';
import { BRAND } from '../brand.js';
import { countBySeverity, grade, postureScore, targetLabel, where } from './common.js';

const esc = (s: string): string =>
  s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

const CSS = `
:root{--bg:#f6f7f9;--card:#fff;--text:#16181d;--muted:#5b6370;--line:#e3e6ea;--accent:#0b6b4f;--code:#f1f3f5;
--critical:#b3123a;--high:#d6402b;--medium:#c27c0e;--low:#2c6fbb;--info:#6b7280}
@media(prefers-color-scheme:dark){:root{--bg:#101215;--card:#181b20;--text:#e8eaed;--muted:#9aa3af;--line:#2a2f37;--accent:#4cc9a0;--code:#0d0f12;
--critical:#ff5c86;--high:#ff8266;--medium:#f0b34a;--low:#6fa8ee;--info:#9aa3af}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.2rem;margin:32px 0 12px}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:12px 0}
.head{display:flex;flex-wrap:wrap;gap:16px;align-items:center;justify-content:space-between}
.grade{font-size:2.4rem;font-weight:700;color:var(--accent);line-height:1}
.pills{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.pill{border:1px solid var(--line);border-radius:999px;padding:2px 12px;font-size:.85rem}
.sev{display:inline-block;border-radius:4px;padding:1px 8px;font-size:.75rem;font-weight:700;color:#fff;text-transform:uppercase}
.sev.critical{background:var(--critical)}.sev.high{background:var(--high)}.sev.medium{background:var(--medium)}.sev.low{background:var(--low)}.sev.info{background:var(--info)}
details{border:1px solid var(--line);border-radius:10px;background:var(--card);margin:10px 0}
summary{cursor:pointer;padding:12px 16px;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
details>div{padding:0 16px 16px}
pre{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;font:13px/1.45 ui-monospace,Menlo,Consolas,monospace}
code{font:13px ui-monospace,Menlo,Consolas,monospace}
table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}
.kv{display:grid;grid-template-columns:110px 1fr;gap:4px 12px;margin:8px 0}.kv b{color:var(--muted);font-weight:600}
@media(max-width:560px){.kv{grid-template-columns:1fr}}
`;

function findingBlock(f: Finding): string {
  const examples = f.advice.examples
    .map(
      (e) =>
        `<p class="muted" style="margin:12px 0 4px">${esc(e.label)}</p><pre><code>${esc(e.code)}</code></pre>`,
    )
    .join('');
  return `<details id="${esc(f.id)}"><summary><span class="sev ${f.severity}">${f.severity}</span><strong>${esc(f.title)}</strong><span class="muted">${esc(where(f))} · risk ${f.risk}</span></summary><div>
<div class="kv"><b>Evidence</b><span>${esc(f.evidence)}</span><b>Certainty</b><span>${f.confidence} — ${f.verified ? 'observed fact' : 'pattern match, not proven'}</span>${f.cwe.length + f.owasp.length ? `<b>Standards</b><span>${esc([...f.cwe, ...f.owasp].join(', '))}</span>` : ''}</div>
<p><strong>Fix:</strong> ${esc(f.advice.summary)}</p><p>${esc(f.advice.why)}</p>
${f.advice.steps.length ? `<ol>${f.advice.steps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>` : ''}${examples}
<p><strong>Verify:</strong> ${esc(f.advice.verify)}</p>
${f.advice.references.length ? `<p class="muted">${f.advice.references.map((r) => `<a href="${esc(r)}" rel="noopener noreferrer">${esc(r)}</a>`).join(' · ')}</p>` : ''}
<p class="muted"><small>How this was checked: ${esc(f.verification)}</small></p></div></details>`;
}

export function renderHtml(result: ScanResult): string {
  const score = postureScore(result.findings);
  const counts = countBySeverity(result.findings);
  const pills = SEVERITIES.map(
    (s: Severity) => `<span class="pill"><span class="sev ${s}">${s}</span> ${counts[s]}</span>`,
  ).join('');
  const insights = result.insights
    .map(
      (i) =>
        `<div class="card"><span class="sev ${i.severity}">${i.severity}</span> <strong>${esc(i.title)}</strong><p>${esc(i.narrative)}</p><p><strong>Do this:</strong> ${esc(i.recommendation)}</p></div>`,
    )
    .join('');
  const plan = result.fixPlan
    .map(
      (s) =>
        `<tr><td>${s.order}</td><td><span class="sev ${s.severity}">${s.severity}</span></td><td>${esc(s.title)}</td><td>${s.effort}</td><td>${s.findingIds.length}</td></tr>`,
    )
    .join('');
  const bundles = result.fixBundles
    .map(
      (b) =>
        `<div class="card"><strong>${esc(b.title)}</strong> <span class="muted">→ ${esc(b.location)} · resolves ${b.covers.length} finding(s)</span><pre><code>${esc(b.code)}</code></pre><p class="muted">${esc(b.note)}</p></div>`,
    )
    .join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(BRAND.name)} security report</title><style>${CSS}</style></head><body><main>
<div class="head"><div><h1>${esc(BRAND.name)} security report</h1><div class="muted">${result.targets.map((t) => esc(targetLabel(t))).join(' · ')}</div><div class="muted">${esc(result.startedAt)} · v${esc(result.tool.version)}</div></div>
<div style="text-align:right"><div class="grade">${grade(score)}</div><div class="muted">${score}/100 posture</div></div></div>
<div class="pills">${pills}</div>
${result.stack.detected.length ? `<p class="muted">Detected stack: ${esc(result.stack.detected.map((d) => d.label).join(', '))}. Fix examples are tailored to it.</p>` : ''}
${insights ? `<h2>What matters most</h2>${insights}` : ''}
${plan ? `<h2>Fix plan</h2><div class="card"><table><thead><tr><th>#</th><th>Severity</th><th>Action</th><th>Effort</th><th>Findings</th></tr></thead><tbody>${plan}</tbody></table></div>` : ''}
${bundles ? `<h2>Ready-to-paste fixes</h2>${bundles}` : ''}
<h2>Findings (${result.findings.length})</h2>
${result.findings.length ? result.findings.map(findingBlock).join('') : '<p class="muted">No findings from the checks that ran.</p>'}
<h2>Not assessed</h2><ul>${result.notAssessed.map((n) => `<li>${esc(n)}</li>`).join('')}</ul>
<p class="muted"><small>Generated by ${esc(BRAND.name)}. Findings marked "pattern match" need human review. Use only on systems you own or are authorised to test.</small></p>
</main></body></html>`;
}
