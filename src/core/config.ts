import { promises as fs } from 'node:fs';
import path from 'node:path';
import { BRAND } from '../brand.js';
import { UserError } from '../errors.js';
import { isRecord } from '../util/json.js';
import type { CodeRule } from '../scanners/code/rules.js';
import { anyCode } from '../scanners/code/rules.js';
import { isSeverity, type Severity } from './types.js';

export interface KingaConfig {
  /** Rule ids never reported (for example `WEB-HDR-004`). */
  ignoreRules: string[];
  /** Project-relative path prefixes or `*` globs skipped in findings. */
  ignorePaths: string[];
  failOn?: Severity;
  /** Extra advisories JSON file, relative to the config file. */
  advisoriesFile?: string;
  customRules: CodeRule[];
  /** Path to the baseline file relative to the config file. */
  baseline?: string;
  source?: string;
}

export const EMPTY_CONFIG: KingaConfig = { ignoreRules: [], ignorePaths: [], customRules: [] };

function strings(value: unknown, name: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((v) => typeof v !== 'string'))
    throw new UserError(`${BRAND.configFile}: "${name}" must be an array of strings.`);
  return value as string[];
}

function parseCustomRule(raw: unknown, i: number): CodeRule {
  const where = `${BRAND.configFile}: customRules[${i}]`;
  if (!isRecord(raw)) throw new UserError(`${where} must be an object.`);
  const { id, title, pattern, severity } = raw;
  if (typeof id !== 'string' || !/^[A-Z][A-Z0-9-]{2,}$/.test(id))
    throw new UserError(`${where}.id must look like CUSTOM-001.`);
  if (typeof title !== 'string' || title === '') throw new UserError(`${where}.title is required.`);
  if (typeof pattern !== 'string')
    throw new UserError(`${where}.pattern must be a regular expression string.`);
  if (typeof severity !== 'string' || !isSeverity(severity))
    throw new UserError(`${where}.severity must be critical, high, medium, low or info.`);
  let re: RegExp;
  try {
    re = new RegExp(pattern);
  } catch (error) {
    throw new UserError(
      `${where}.pattern is not a valid regular expression: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const files = typeof raw['files'] === 'string' ? raw['files'] : undefined;
  let fileRe: RegExp | undefined;
  if (files !== undefined) {
    try {
      fileRe = new RegExp(files);
    } catch {
      throw new UserError(`${where}.files must be a valid regular expression matching file paths.`);
    }
  }
  return {
    id,
    kb: typeof raw['kb'] === 'string' ? raw['kb'] : 'custom',
    title,
    severity,
    confidence: 'medium',
    domain: 'code',
    category: typeof raw['category'] === 'string' ? raw['category'] : 'custom',
    pattern: re,
    appliesTo: (p) => (fileRe ? fileRe.test(p) : anyCode(p)),
    note: typeof raw['fix'] === 'string' ? raw['fix'] : undefined,
  };
}

export async function loadConfig(
  explicit: string | undefined,
  searchDirs: readonly string[],
): Promise<KingaConfig> {
  const candidates = explicit
    ? [path.resolve(explicit)]
    : searchDirs.map((d) => path.join(d, BRAND.configFile));
  for (const file of candidates) {
    let text: string;
    try {
      text = await fs.readFile(file, 'utf8');
    } catch (error) {
      if (explicit)
        throw new UserError(
          `Cannot read config ${file}: ${error instanceof Error ? error.message : String(error)}`,
        );
      continue;
    }
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch (error) {
      throw new UserError(
        `${file} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    if (!isRecord(json)) throw new UserError(`${file} must contain a JSON object.`);
    const failOn = json['failOn'];
    if (failOn !== undefined && (typeof failOn !== 'string' || !isSeverity(failOn)))
      throw new UserError(
        `${BRAND.configFile}: "failOn" must be critical, high, medium, low or info.`,
      );
    const rules = json['customRules'];
    if (rules !== undefined && !Array.isArray(rules))
      throw new UserError(`${BRAND.configFile}: "customRules" must be an array.`);
    const dir = path.dirname(file);
    const advisories = json['advisoriesFile'];
    const baseline = json['baseline'];
    return {
      ignoreRules: strings(json['ignoreRules'], 'ignoreRules'),
      ignorePaths: strings(json['ignorePaths'], 'ignorePaths'),
      ...(failOn ? { failOn: failOn as Severity } : {}),
      ...(typeof advisories === 'string' ? { advisoriesFile: path.resolve(dir, advisories) } : {}),
      ...(typeof baseline === 'string' ? { baseline: path.resolve(dir, baseline) } : {}),
      customRules: ((rules as unknown[] | undefined) ?? []).map(parseCustomRule),
      source: file,
    };
  }
  return { ...EMPTY_CONFIG };
}

export function pathIgnored(config: KingaConfig, target: string): boolean {
  return config.ignorePaths.some((pattern) => {
    if (!pattern.includes('*'))
      return (
        target === pattern || target.startsWith(pattern.endsWith('/') ? pattern : `${pattern}/`)
      );
    const re = new RegExp(
      `^${pattern
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*\*/g, '§§')
        .replace(/\*/g, '[^/]*')
        .replace(/§§/g, '.*')}$`,
    );
    return re.test(target);
  });
}

export async function loadBaseline(file: string): Promise<Set<string>> {
  try {
    const json: unknown = JSON.parse(await fs.readFile(file, 'utf8'));
    if (isRecord(json) && Array.isArray(json['fingerprints']))
      return new Set(json['fingerprints'].filter((x): x is string => typeof x === 'string'));
  } catch {
    // a missing or unreadable baseline simply suppresses nothing
  }
  return new Set();
}

export const DEFAULT_CONFIG_TEXT = `{
  "failOn": "high",
  "ignoreRules": [],
  "ignorePaths": ["vendor/", "**/*.generated.*"],
  "baseline": ".kinga/baseline.json",
  "customRules": [
    {
      "id": "CUSTOM-001",
      "title": "Internal admin URL hard-coded",
      "pattern": "https?://admin\\\\.internal\\\\.example\\\\.com",
      "severity": "low",
      "files": "\\\\.(js|ts|py)$"
    }
  ]
}
`;
