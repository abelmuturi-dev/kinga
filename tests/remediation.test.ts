import { describe, expect, it } from 'vitest';
import { previewSafeRemediation } from '../src/assurance/remediation.js';

describe('safe remediation previews', () => {
  it('creates a review-only noopener patch for a target blank anchor', () => {
    const preview = previewSafeRemediation(
      'CODE-WEB-002',
      'src/page.html',
      '<a href="/out" target="_blank">Open</a>',
      1,
    );
    expect(preview?.patch).toContain('rel="noopener noreferrer"');
    expect(preview?.patch).toContain('--- a/src/page.html');
  });

  it('preserves existing rel values and does not duplicate noopener', () => {
    const preview = previewSafeRemediation(
      'CODE-WEB-002',
      'src/page.html',
      '<a target="_blank" rel="noreferrer">Open</a>',
      1,
    );
    expect(preview?.patch).toContain('rel="noreferrer noopener"');
    expect(
      previewSafeRemediation(
        'CODE-WEB-002',
        'src/page.html',
        '<a target="_blank" rel="noopener">Open</a>',
        1,
      ),
    ).toBeNull();
  });

  it('refuses unsupported rules and malformed locations', () => {
    expect(previewSafeRemediation('CODE-INJ-001', 'src/a.ts', 'exec(input)', 1)).toBeNull();
    expect(
      previewSafeRemediation('CODE-WEB-002', 'src/a.html', '<a target="_blank">x</a>', 0),
    ).toBeNull();
  });
});
