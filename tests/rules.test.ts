import { describe, expect, it } from 'vitest';
import { CODE_RULES } from '../src/scanners/code/rules.js';

function hits(id: string, path: string, line: string): boolean {
  const rule = CODE_RULES.find((r) => r.id === id);
  if (!rule) throw new Error(`no rule ${id}`);
  if (!rule.appliesTo(path)) return false;
  const m = new RegExp(rule.pattern.source, rule.pattern.flags).exec(line);
  return m !== null && (rule.accept ? rule.accept(line, m) : true);
}

describe('rule precision (true and false positives)', () => {
  const cases: Array<[string, string, string, boolean]> = [
    // ReDoS: only a single repeating atom inside a repeated group is catastrophic.
    ['CODE-RGX-001', 'a.js', 'const re = /^(a+)+$/;', true],
    ['CODE-RGX-001', 'a.js', 'const re = /^(\\d+)*$/;', true],
    ['CODE-RGX-001', 'a.js', 'const re = /^(\\d+(?:\\.\\d+)*)/;', false],
    ['CODE-RGX-001', 'a.js', 'const re = /^=?\\s*v?\\d+(?:\\.\\d+)+$/;', false],
    // eval needs an argument to be a call.
    ['CODE-INJ-004', 'a.js', 'eval(userInput)', true],
    ['CODE-INJ-004', 'a.js', 'title: "CSP allows eval() blocked"', false],
    ['CODE-INJ-004', 'a.js', 'page.evaluate(x)', false],
    // exec(): Python only.
    ['CODE-INJ-007', 'a.py', 'exec(code)', true],
    ['CODE-INJ-007', 'a.js', 'exec(code)', false],
    // SameSite=None only when code sets it, not when prose mentions it.
    ['CODE-AUT-001', 'a.js', "cookie: { sameSite: 'none' }", true],
    ['CODE-AUT-001', 'a.js', "msg: 'SameSite=None requires Secure'", false],
    // SQL, command and TLS checks.
    ['CODE-INJ-002', 'a.js', 'db.query(`SELECT * FROM t WHERE id = ${id}`)', true],
    ['CODE-INJ-002', 'a.js', "db.query('SELECT * FROM t WHERE id = $1', [id])", false],
    ['CODE-INJ-001', 'a.py', 'os.system("ping " + host)', true],
    ['CODE-INJ-001', 'a.py', 'subprocess.run(["ping", host])', false],
    ['CODE-DES-001', 'a.py', 'data = yaml.load(text)', true],
    ['CODE-DES-001', 'a.py', 'data = yaml.safe_load(text)', false],
    ['CODE-CRY-004', 'a.py', 'requests.get(u, verify=False)', true],
    ['CODE-CRY-004', 'a.py', 'requests.get(u, verify=True)', false],
    ['CODE-SEC-001', 'a.js', 'const apiKey = "Xk29fj38dkQpz01";', true],
    ['CODE-SEC-001', 'a.js', 'const apiKey = process.env.API_KEY;', false],
    ['CODE-SEC-001', 'a.js', 'const password = "your-password-here";', false],
  ];
  it.each(cases)('%s on %s: %s -> %s', (id, path, line, expected) => {
    expect(hits(id, path, line)).toBe(expected);
  });

  it('every rule has a unique id, a knowledge-base topic and a compiling pattern', async () => {
    const { TOPICS } = await import('../src/engine/advisor.js');
    const ids = new Set<string>();
    for (const r of CODE_RULES) {
      expect(ids.has(r.id), `duplicate ${r.id}`).toBe(false);
      ids.add(r.id);
      expect(TOPICS[r.kb], `${r.id} -> ${r.kb}`).toBeDefined();
    }
  });
});
