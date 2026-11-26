import { describe, expect, it } from 'vitest';
import { AdvisoryDb } from '../src/scanners/deps/advisories.js';
import {
  compareVersions,
  inRange,
  isExactVersion,
  parseRanges,
  parseVersion,
} from '../src/scanners/deps/version.js';

describe('version handling', () => {
  it('parses and compares dotted versions', () => {
    expect(parseVersion('^4.17.1')).toEqual([4, 17, 1]);
    expect(compareVersions([4, 17, 9], [4, 17, 10])).toBe(-1);
    expect(compareVersions([2, 0], [2, 0, 0])).toBe(0);
    expect(parseVersion('latest')).toBeNull();
  });
  it('evaluates ranges with an exclusive upper bound', () => {
    const [r] = parseRanges('>=1.0.0 <1.2.6');
    expect(inRange('1.2.5', r!)).toBe(true);
    expect(inRange('1.2.6', r!)).toBe(false);
    expect(inRange('0.9.0', r!)).toBe(false);
  });
  it('handles alternative ranges', () => {
    const ranges = parseRanges('<0.2.4 || >=1.0.0 <1.2.6');
    expect(ranges).toHaveLength(2);
  });
  it('recognises exact pins', () => {
    expect(isExactVersion('1.2.3')).toBe(true);
    expect(isExactVersion('^1.2.3')).toBe(false);
  });
});

describe('advisory database', () => {
  const db = new AdvisoryDb();
  it('finds a known vulnerable version and the fixed version', () => {
    const hits = db.lookup('npm', 'minimist', '1.2.5');
    expect(hits[0]?.advisory.id).toBe('CVE-2021-44906');
    expect(hits[0]?.fixedIn).toBe('1.2.6');
  });
  it('does not flag fixed versions', () => {
    expect(db.lookup('npm', 'minimist', '1.2.6')).toHaveLength(0);
  });
  it('normalises PyPI names', () => {
    expect(db.lookup('pypi', 'PyYAML', '5.3').length).toBeGreaterThan(0);
  });
  it('matches Log4Shell in Maven coordinates', () => {
    expect(
      db.lookup('maven', 'org.apache.logging.log4j:log4j-core', '2.14.1')[0]?.advisory.severity,
    ).toBe('critical');
  });
});
