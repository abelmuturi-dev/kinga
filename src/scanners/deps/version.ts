/** Minimal version handling: numeric dotted versions, which is what advisory ranges need. */

export function parseVersion(input: string): number[] | null {
  const cleaned = input.trim().replace(/^[=v^~\s]+/, '');
  const m = /^(\d+(?:\.\d+)*)/.exec(cleaned);
  if (!m?.[1]) return null;
  return m[1].split('.').map((n) => Number.parseInt(n, 10));
}

export function compareVersions(a: readonly number[], b: readonly number[]): number {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

export interface VersionRange {
  /** Inclusive lower bound. */
  introduced?: string;
  /** Exclusive upper bound: the first fixed version. */
  fixed: string;
}

/** Parses `<1.2.3`, `>=1.0.0 <1.2.3` and `||`-joined alternatives. */
export function parseRanges(spec: string): VersionRange[] {
  const ranges: VersionRange[] = [];
  for (const part of spec.split('||')) {
    const lower = /(?:>=)\s*([\w.+-]+)/.exec(part);
    const upper = /(?:<)(?!=)\s*([\w.+-]+)/.exec(part);
    if (!upper?.[1]) continue;
    ranges.push({ ...(lower?.[1] ? { introduced: lower[1] } : {}), fixed: upper[1] });
  }
  return ranges;
}

export function inRange(version: string, range: VersionRange): boolean {
  const v = parseVersion(version);
  if (!v) return false;
  const fixed = parseVersion(range.fixed);
  if (!fixed || compareVersions(v, fixed) >= 0) return false;
  if (range.introduced !== undefined) {
    const intro = parseVersion(range.introduced);
    if (intro && compareVersions(v, intro) < 0) return false;
  }
  return true;
}

/** True when the specifier pins one exact version (`1.2.3` or `=1.2.3`), with no range operators. */
export function isExactVersion(spec: string): boolean {
  return /^=?\s*v?\d+(?:\.\d+)+$/.test(spec.trim());
}
