import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { TOPICS } from '../src/engine/advisor.js';

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith('.ts')) out.push(p);
  }
  return out;
}

describe('knowledge-base coverage', () => {
  it('every kb key used by a scanner has a topic (no silent fallback advice)', () => {
    const used = new Map<string, string>();
    for (const file of walk('src/scanners')) {
      for (const m of readFileSync(file, 'utf8').matchAll(/\bkb:\s*'([a-z0-9-]+)'/g))
        used.set(m[1]!, file);
    }
    expect(used.size).toBeGreaterThan(60);
    const missing = [...used]
      .filter(([k]) => k !== 'custom' && !TOPICS[k])
      .map(([k, f]) => `${k} (${f})`);
    expect(missing).toEqual([]);
  });

  it('every topic is used by at least one scanner (no dead guidance)', () => {
    const src = walk('src/scanners')
      .map((f) => readFileSync(f, 'utf8'))
      .join('\n');
    const unused = Object.keys(TOPICS).filter((k) => !src.includes(`'${k}'`));
    expect(unused).toEqual([]);
  });
});
