import { homedir } from 'node:os';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import type { Context } from '../context.js';
import { UsageError, UserError } from '../errors.js';
import {
  auditApiContract,
  buildComplianceReport,
  buildCycloneDx,
  compareScanResults,
  inspectDns,
  inspectJavaScriptAsset,
  loadScanResult,
  rephraseWithLocalModel,
  saveScanHistory,
  scanGitHistory,
  previewSafeRemediation,
  scanBomWithOsv,
  writeCycloneDx,
} from '../assurance/index.js';

export async function assuranceCommand(args: string[], ctx: Context): Promise<number> {
  const [action, ...rest] = args;
  if (!action)
    throw new UsageError(
      'Usage: kinga assurance <sbom|osv|dns|js|api|git-secrets|fix-preview|compare|compliance|history|rephrase> ...',
    );
  if (action === 'sbom') {
    const root = path.resolve(ctx.cwd, rest[0] ?? '.');
    const output = rest[1] ? path.resolve(ctx.cwd, rest[1]) : path.join(ctx.cwd, 'bom.json');
    if (!(await fs.stat(root).catch(() => null))?.isDirectory())
      throw new UserError(`Not a project directory: ${root}`);
    const bom = await buildCycloneDx(root);
    await writeCycloneDx(bom, output);
    ctx.print(`CycloneDX 1.5 SBOM written to ${output} (${bom.components.length} components).`);
    return 0;
  }
  if (action === 'osv') {
    if (!rest[0])
      throw new UsageError(
        'Usage: kinga assurance osv <bom.json> [--offline|--refresh] [cache.json]',
      );
    const input = path.resolve(ctx.cwd, rest[0]);
    const offline = rest.includes('--offline');
    const refresh = rest.includes('--refresh');
    const cacheArg = rest.find((item) => !['--offline', '--refresh', rest[0]].includes(item));
    const cache = path.resolve(
      ctx.cwd,
      cacheArg ?? path.join(homedir(), '.kinga', 'osv-cache.json'),
    );
    const bom = JSON.parse(await fs.readFile(input, 'utf8'));
    if (bom.bomFormat !== 'CycloneDX' || !Array.isArray(bom.components))
      throw new UserError('Input must be a CycloneDX BOM.');
    ctx.print(JSON.stringify(await scanBomWithOsv(bom, cache, offline, refresh), null, 2));
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
  if (action === 'git-secrets') {
    const maxIndex = rest.indexOf('--max-commits');
    if (maxIndex >= 0 && !rest[maxIndex + 1]) {
      throw new UsageError('Usage: kinga assurance git-secrets [directory] [--max-commits <1-5000>]');
    }
    const directory =
      rest.find(
        (item, index) =>
          !item.startsWith('--') && !(maxIndex >= 0 && index === maxIndex + 1),
      ) ?? '.';
    const maxCommits = maxIndex >= 0 ? Number(rest[maxIndex + 1]) : 100;
    if (!Number.isInteger(maxCommits) || maxCommits < 1 || maxCommits > 5000) {
      throw new UsageError('--max-commits must be an integer between 1 and 5000.');
    }
    try {
      const report = scanGitHistory(path.resolve(ctx.cwd, directory), maxCommits);
      ctx.print(JSON.stringify(report, null, 2));
    } catch (error) {
      throw new UserError(error instanceof Error ? error.message : String(error));
    }
    return 0;
  }
  if (action === 'api') {
    if (!rest[0])
      throw new UsageError('Usage: kinga assurance api <openapi.json> [output.json]');
    const input = path.resolve(ctx.cwd, rest[0]);
    const stat = await fs.stat(input).catch(() => null);
    if (!stat?.isFile()) throw new UserError(`Not an API contract file: ${input}`);
    if (stat.size > 5_000_000) {
      throw new UserError('API contract exceeds the 5 MB safety limit.');
    }

    let document: unknown;
    try {
      document = JSON.parse(await fs.readFile(input, 'utf8'));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new UserError(`Could not parse API contract JSON: ${message}`);
    }

    const report = auditApiContract(document);
    const json = `${JSON.stringify(report, null, 2)}\n`;
    if (rest[1]) {
      await fs.writeFile(path.resolve(ctx.cwd, rest[1]), json, {
        encoding: 'utf8',
        mode: 0o600,
      });
      ctx.print(`API contract report written to ${rest[1]} (${report.issues.length} issues).`);
    } else {
      ctx.print(json);
    }
    return 0;
  }
  if (action === 'fix-preview') {
    if (!rest[0] || rest[1] === undefined) {
      throw new UsageError(
        'Usage: kinga assurance fix-preview <scan.json> <finding-index> [output.patch]',
      );
    }
    const result = await loadScanResult(path.resolve(ctx.cwd, rest[0]));
    const index = Number(rest[1]);
    const finding = result.findings[index];
    if (!Number.isInteger(index) || !finding) {
      throw new UsageError('Finding index is out of range.');
    }
    if (!finding.line || !finding.target || finding.domain === 'web') {
      throw new UserError('This finding has no supported source-file location.');
    }
    const sourcePath = path.resolve(ctx.cwd, finding.target);
    const relative = path.relative(ctx.cwd, sourcePath);
    if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) {
      throw new UserError('Refusing to preview a patch outside the current project directory.');
    }
    const stat = await fs.stat(sourcePath).catch(() => null);
    if (!stat?.isFile() || stat.size > 2_000_000) {
      throw new UserError('Source file is missing or exceeds the 2 MB preview limit.');
    }
    const source = await fs.readFile(sourcePath, 'utf8');
    const preview = previewSafeRemediation(
      finding.rule,
      finding.target,
      source,
      finding.line,
    );
    if (!preview) {
      throw new UserError(
        'No safe automatic preview is available for this rule or source line. Apply a manual fix using the finding guidance.',
      );
    }
    if (rest[2]) {
      const output = path.resolve(ctx.cwd, rest[2]);
      await fs.writeFile(output, `${preview.patch}\n`, {
        encoding: 'utf8',
        mode: 0o600,
        flag: 'wx',
      });
      ctx.print(`Review-only patch written to ${output}; source files were not changed.`);
    } else {
      ctx.print(preview.patch);
      ctx.print(ctx.style.dim('Preview only. Kinga did not modify the source file.'));
    }
    return 0;
  }
  if (action === 'compare') {
    if (!rest[0] || !rest[1])
      throw new UsageError('Usage: kinga assurance compare <previous.json> <current.json>');
    const [previous, current] = await Promise.all([
      loadScanResult(path.resolve(ctx.cwd, rest[0])),
      loadScanResult(path.resolve(ctx.cwd, rest[1])),
    ]);
    const delta = compareScanResults(previous, current);
    ctx.print(
      JSON.stringify(
        {
          previousFindings: delta.previousCount,
          currentFindings: delta.currentCount,
          added: delta.added.map((f) => ({
            rule: f.rule,
            title: f.title,
            severity: f.severity,
            target: f.target,
          })),
          resolved: delta.resolved.map((f) => ({
            rule: f.rule,
            title: f.title,
            severity: f.severity,
            target: f.target,
          })),
          persisting: delta.persisting.length,
        },
        null,
        2,
      ),
    );
    return 0;
  }
  if (action === 'compliance') {
    if (!rest[0])
      throw new UsageError('Usage: kinga assurance compliance <scan.json> [output.json]');
    const result = await loadScanResult(path.resolve(ctx.cwd, rest[0]));
    const json = `${JSON.stringify(buildComplianceReport(result.findings), null, 2)}\n`;
    if (rest[1]) {
      await fs.writeFile(path.resolve(ctx.cwd, rest[1]), json, { encoding: 'utf8', mode: 0o600 });
      ctx.print(`Indicative compliance mapping written to ${rest[1]}.`);
    } else ctx.print(json);
    return 0;
  }
  if (action === 'history') {
    const directory = path.join(homedir(), '.kinga', 'history');
    if (rest[0] === 'list') {
      const names = (await fs.readdir(directory).catch(() => []))
        .filter((name) => name.endsWith('.json'))
        .sort()
        .reverse();
      ctx.print(names.length ? names.join(' | ') : 'No local scan history yet.');
      return 0;
    }
    if (rest[0] === 'compare') {
      const names = (await fs.readdir(directory).catch(() => []))
        .filter((name) => name.endsWith('.json'))
        .sort()
        .reverse();
      if (names.length < 2)
        throw new UserError('At least two saved scans are needed for a history comparison.');
      const current = await loadScanResult(path.join(directory, names[0]!));
      const previous = await loadScanResult(path.join(directory, names[1]!));
      const delta = compareScanResults(previous, current);
      ctx.print(
        JSON.stringify(
          {
            previousFindings: delta.previousCount,
            currentFindings: delta.currentCount,
            added: delta.added.length,
            resolved: delta.resolved.length,
            persisting: delta.persisting.length,
          },
          null,
          2,
        ),
      );
      return 0;
    }
    if (!rest[0]) throw new UsageError('Usage: kinga assurance history <scan.json|list|compare>');
    const result = await loadScanResult(path.resolve(ctx.cwd, rest[0]));
    const file = await saveScanHistory(directory, result);
    ctx.print(`Local scan snapshot saved to ${file}.`);
    return 0;
  }
  if (action === 'rephrase') {
    if (!rest[0] || !rest[1] || !rest[2])
      throw new UsageError(
        'Usage: kinga assurance rephrase <scan.json> <finding-index> <ollama-model>',
      );
    const result = await loadScanResult(path.resolve(ctx.cwd, rest[0]));
    const index = Number(rest[1]);
    const finding = result.findings[index];
    if (!Number.isInteger(index) || !finding)
      throw new UsageError('Finding index is out of range.');
    const output = await rephraseWithLocalModel(
      {
        summary: finding.advice.summary,
        why: finding.advice.why,
        steps: finding.advice.steps,
        verify: finding.advice.verify,
      },
      rest[2],
    );
    ctx.print(output);
    ctx.print(
      ctx.style.dim(
        'Optional local-model wording only; Kinga findings and original remediation remain unchanged.',
      ),
    );
    return 0;
  }
  throw new UsageError(
    `Unknown assurance action "${action}". Use sbom, osv, dns, js, api, git-secrets, fix-preview, compare, compliance, history or rephrase.`,
  );
}
