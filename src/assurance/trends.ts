import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { Finding, ScanResult } from '../core/types.js';

export interface ScanDelta {
  added: Finding[];
  resolved: Finding[];
  persisting: Finding[];
  previousCount: number;
  currentCount: number;
}
export function compareScanResults(previous: ScanResult, current: ScanResult): ScanDelta {
  const old = new Set(previous.findings.map((finding) => finding.fingerprint));
  const now = new Set(current.findings.map((finding) => finding.fingerprint));
  return {
    added: current.findings.filter((finding) => !old.has(finding.fingerprint)),
    resolved: previous.findings.filter((finding) => !now.has(finding.fingerprint)),
    persisting: current.findings.filter((finding) => old.has(finding.fingerprint)),
    previousCount: previous.findings.length,
    currentCount: current.findings.length,
  };
}
export async function saveScanHistory(directory: string, result: ScanResult): Promise<string> {
  const dir = path.resolve(directory);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const file = path.join(dir, `${result.startedAt.replace(/[:.]/g, '-')}.json`);
  await writeFile(file, `${JSON.stringify(result, null, 2)}\n`, {
    encoding: 'utf8',
    mode: 0o600,
    flag: 'wx',
  });
  return file;
}
export async function loadScanResult(file: string): Promise<ScanResult> {
  const value: unknown = JSON.parse(await readFile(file, 'utf8'));
  if (
    typeof value !== 'object' ||
    value === null ||
    !Array.isArray((value as { findings?: unknown }).findings)
  ) {
    throw new Error(`Invalid Kinga scan result: ${file}`);
  }
  return value as ScanResult;
}
