import { execFileSync } from 'node:child_process';
import path from 'node:path';

export type GitSecretKind =
  | 'private-key'
  | 'aws-access-key'
  | 'github-token'
  | 'slack-token'
  | 'google-api-key'
  | 'stripe-secret-key'
  | 'generic-secret';

export interface GitSecretFinding {
  kind: GitSecretKind;
  severity: 'critical' | 'high' | 'medium';
  commit: string;
  file: string;
  line: number;
  evidence: string;
}

export interface GitHistorySecretReport {
  directory: string;
  commitsScanned: number;
  findings: GitSecretFinding[];
  notes: string[];
}

const PATTERNS: Array<[GitSecretKind, GitSecretFinding['severity'], RegExp]> = [
  ['private-key', 'critical', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ['aws-access-key', 'high', /\bAKIA[0-9A-Z]{16}\b/],
  ['github-token', 'high', /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/],
  ['slack-token', 'high', /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/],
  ['google-api-key', 'high', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['stripe-secret-key', 'high', /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/],
  [
    'generic-secret',
    'medium',
    /\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|secret)\b\s*[:=]\s*["']?(?!\$\{|<|your_|changeme|example|placeholder)[A-Za-z0-9_./+=-]{12,}/i,
  ],
];

/** Inspect added lines in a git patch. Secret values are never copied into findings. */
export function inspectGitPatch(patch: string): GitHistorySecretReport['findings'] {
  const findings: GitHistorySecretReport['findings'] = [];
  const seen = new Set<string>();
  let commit = 'unknown';
  let file = '';
  let lineNumber = 0;
  let inHunk = false;

  for (const line of patch.split(/\r?\n/)) {
    if (line.startsWith('commit ')) {
      commit = line.slice(7, 19);
      inHunk = false;
      continue;
    }
    if (line.startsWith('+++ b/')) {
      file = line.slice(6);
      continue;
    }
    if (line.startsWith('+++ /dev/null')) {
      file = '';
      continue;
    }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
    if (hunk?.[1]) {
      lineNumber = Number(hunk[1]);
      inHunk = true;
      continue;
    }
    if (!inHunk || !file) continue;
    if (line.startsWith('+++') || line.startsWith('---') || line.startsWith('\\')) continue;

    if (line.startsWith('+')) {
      const added = line.slice(1);
      for (const [kind, severity, pattern] of PATTERNS) {
        if (!pattern.test(added)) continue;
        const key = `${commit}| ${file}|${lineNumber}|${kind}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          kind,
          severity,
          commit,
          file,
          line: lineNumber,
          evidence: 'Potential secret in a historical addition; the value is redacted.',
        });
      }
      lineNumber++;
    } else if (line.startsWith(' ')) {
      lineNumber++;
    }
  }

  return findings;
}

/**
 * Scan recent reachable Git history without contacting remotes or validating credentials.
 * The git command is invoked with fixed arguments (no shell) and a strict output/time budget.
 */
export function scanGitHistory(directory: string, maxCommits = 100): GitHistorySecretReport {
  if (!Number.isInteger(maxCommits) || maxCommits < 1 || maxCommits > 5000) {
    throw new Error('maxCommits must be an integer between 1 and 5000.');
  }

  const absolute = path.resolve(directory);
  let patch: string;
  try {
    patch = execFileSync(
      'git',
      [
        'log',
        '--all',
        '--format=commit %H',
        '--no-ext-diff',
        '--no-textconv',
        '--no-renames',
        '-p',
        `--max-count=${maxCommits}`,
      ],
      {
        cwd: absolute,
        encoding: 'utf8',
        maxBuffer: 25 * 1024 * 1024,
        timeout: 30_000,
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
  } catch {
    throw new Error(
      'Could not read Git history. Check that Git is installed and the directory is a Git repository.',
    );
  }

  const commitsScanned = new Set(
    patch
      .split(/\r?\n/)
      .filter((line) => line.startsWith('commit '))
      .map((line) => line.slice(7, 19)),
  ).size;
  const findings = inspectGitPatch(patch);
  return {
    directory: absolute,
    commitsScanned,
    findings,
    notes: [
      'Only added lines in reachable local Git history were inspected.',
      'No remote fetches or secret-validity checks were performed.',
      'Finding values are never included; rotate any credential that may have been committed.',
    ],
  };
}
