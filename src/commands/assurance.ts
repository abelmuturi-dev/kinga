import { homedir } from 'node:os';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import type { Context } from '../context.js';
import { UsageError, UserError } from '../errors.js';
import {
  buildComplianceReport, buildCycloneDx, compareScanResults, inspectDns,
  inspectJavaScriptAsset, loadScanResult, rephraseWithLocalModel,
  saveScanHistory, scanBomWithOsv, writeCycloneDx,
} from '../assurance/index.js';

export async function assuranceCommand(args: string[], ctx: Context): Promise<number> {
  const [action, ...rest] = args;
  if (!action) throw new UsageError('Usage: kinga assurance <sbom|osv|dns|js|compare|compliance|history|rephrase> ...');
  if (action === 'sbom') {
    const root = path.resolve(ctx.cwd, rest[0] ?? '.');
    const output = rest[1] ? path.resolve(ctx.cwd, rest[1]) : path.join(ctx.cwd, 'bom.json');
    if (!(await fs.stat(root).catch(() => null))?.isDirectory()) throw new UserError(`Not a project directory: ${root}`);
    const bom = await buildCycloneDx(root);
    await writeCycloneDx(bom, output);
    ctx.print(`CycloneDX 1.5 SBOM written to ${output} (${bom.components.length} components).`);
    return 0;
  }
  if (action === 'osv') {
    if (!rest[0]) throw new UsageError('Usage: kinga assurance osv <bom.json> [--offline] [cache.json]');
    const input = path.resolve(ctx.cwd, rest[0]);
    const offline = rest.includes('--offline');
    const cacheArg = rest.find((item) => item !== '--offline' && item !== rest[0]);
    const cache = path.resolve(ctx.cwd, cacheArg ?? path.join(homedir(), '.kinga', 'osv-cache.json'));
    const bom = JSON.parse(await fs.readFile(input, 'utf8'));
    if (bom.bomFormat !== 'CycloneDX' || !Array.isArray(bom.components)) throw new UserError('Input must be a CycloneDX BOM.');
    ctx.print(JSON.stringify(await scanBomWithOsv(bom, cache, offline), null, 2));
    return 0;
  }
  if (action === 'dns') {
    if (!rest[0]) throw new UsageError('Usage: kinga assurance dns <domain>');
    ctx.print(JSON.stringify(await inspectDns(rest[0]), null, 2));
    return 0;
  }
  if (action === 'js') {
    if (!rest[0]) throw new UsageError('Usage: kinga assurance js <javascript-file>');
    const source = await fs.readFile(path.resolve(ctx.cwd, rest[0]), 'utf8');
    ctx.print(JSON.stringify(inspectJavaScriptAsset(source), null, 2));
    return 0;
  }
  if (action === 'compare') {
    if (!rest[0] || !rest[1]) throw new UsageError('Usage: kinga assurance compare <previous.json> <current.json>');
    const [previous, current] = await Promise.all([
      loadScanResult(path.resolve(ctx.cwd, rest[0])), loadScanResult(path.resolve(ctx.cwd, rest[1])),
    ]);
    const delta = compareScanResults(previous, current);
    ctx.print(JSON.stringify({
      previousFindings: delta.previousCount, currentFindings: delta.currentCount,
      added: delta.added.map((f) => ({ rule: f.rule, title: f.title, severity: f.severity, target: f.target })),
      resolved: delta.resolved.map((f) => ({ rule: f.rule, title: f.title, severity: f.severity, target: f.target })),
      persisting: delta.persisting.length,
    }, null, 2));
    return 0;
  }
  if (action === 'compliance') {
    if (!rest[0]) throw new UsageError('Usage: kinga assurance compliance <scan.json> [output.json]');
    const result = await loadScanResult(path.resolve(ctx.cwd, rest[0]));
    const json = `${JSON.stringify(buildComplianceReport(result.findings), null, 2)}\n`;
    if (rest[1]) {
      await fs.writeFile(path.resolve(ctx.cwd, rest[1]), json, { encoding: 'utf8', mode: 0o600 });
      ctx.print(`Indicative compliance mapping written to ${rest[1]}.`);
    } else ctx.print(json);
    return 0;
  }
  if (action === 'history') {
    if (!rest[0]) throw new UsageError('Usage: kinga assurance history <scan.json>');
    const result = await loadScanResult(path.resolve(ctx.cwd, rest[0]));
    const file = await saveScanHistory(path.join(homedir(), '.kinga', 'history'), result);
    ctx.print(`Local scan snapshot saved to ${file}.`);
    return 0;
  }
  if (action === 'rephrase') {
    if (!rest[0] || !rest[1] || !rest[2]) throw new UsageError('Usage: kinga assurance rephrase <scan.json> <finding-index> <ollama-model>');
    const result = await loadScanResult(path.resolve(ctx.cwd, rest[0]));
    const index = Number(rest[1]);
    const finding = result.findings[index];
    if (!Number.isInteger(index) || !finding) throw new UsageError('Finding index is out of range.');
    const output = await rephraseWithLocalModel({
      summary: finding.advice.summary, why: finding.advice.why,
      steps: finding.advice.steps, verify: finding.advice.verify,
    }, rest[2]);
    ctx.print(output);
    ctx.print(ctx.style.dim('Optional local-model wording only; Kinga findings and original remediation remain unchanged.'));
    return 0;
  }
  throw new UsageError(`Unknown assurance action "${action}". Use sbom, osv, dns, js, compare, compliance, history or rephrase.`);
}
