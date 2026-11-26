import { describe, expect, it } from 'vitest';
import { analyseTaint } from '../src/scanners/code/taint.js';

describe('AST taint analysis', () => {
  it('tracks request input through a variable into a command sink', () => {
    const flows = analyseTaint(
      'const command = req.query.command;\nexec(command);',
      'sample.ts',
    );
    expect(flows).toHaveLength(1);
    expect(flows[0]?.rule).toBe('CODE-TAINT-001');
    expect(flows[0]?.sink).toBe('exec');
    expect(flows[0]?.line).toBe(2);
    expect(flows[0]?.severity).toBe('high');
  });

  it('does not report a constant passed to a command sink', () => {
    expect(analyseTaint('exec("fixed-command");', 'sample.js')).toHaveLength(0);
  });

  it('tracks tainted values into SQL and DOM sinks', () => {
    const flows = analyseTaint(
      'const value = req.body.name;\ndb.query("SELECT * FROM users WHERE name = " + value);\nelement.innerHTML = value;',
      'sample.ts',
    );
    expect(flows.map((flow) => flow.sink)).toEqual(expect.arrayContaining(['query', 'innerHTML']));
    expect(flows).toHaveLength(2);
  });
});
