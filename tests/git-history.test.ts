import { describe, expect, it } from 'vitest';
import { inspectGitPatch } from '../src/assurance/git-history.js';

describe('Git history secret inspection', () => {
  it('detects known token patterns in added lines and redacts their values', () => {
    const patch = [
      'commit 0123456789abcdef0123456789abcdef01234567',
      'diff --git a/config.ts b/config.ts',
      'index 1111111..2222222 100644',
      '--- a/config.ts',
      '+++ b/config.ts',
      '@@ -1,0 +1,3 @@',
      '+const aws = "AKIAABCDEFGHIJKLMNOP";',
      '+const password = "correct-horse-battery-staple-123";',
      '+const safe = "not a credential";',
    ].join('\n');

    const findings = inspectGitPatch(patch);
    expect(findings.map((finding) => finding.kind)).toEqual(
      expect.arrayContaining(['aws-access-key', 'generic-secret']),
    );
    expect(JSON.stringify(findings)).not.toContain('AKIAABCDEFGHIJKLMNOP');
    expect(JSON.stringify(findings)).not.toContain('correct-horse-battery-staple-123');
  });

  it('ignores deleted lines and detects private-key markers', () => {
    const patch = [
      'commit abcdef0123456789abcdef0123456789abcdef01',
      'diff --git a/keys.pem b/keys.pem',
      '--- a/keys.pem',
      '+++ b/keys.pem',
      '@@ -1 +1 @@',
      '------BEGIN PRIVATE KEY-----',
      '+-----BEGIN RSA PRIVATE KEY-----',
    ].join('\n');

    const findings = inspectGitPatch(patch);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.kind).toBe('private-key');
    expect(findings[0]?.severity).toBe('critical');
  });
});
