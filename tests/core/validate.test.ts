import { describe, expect, test } from 'vitest';
import { expectTypeOf } from 'vitest';
import { validate } from '../../src/core/validate.js';
import type { ValidationResult } from '../../src/core/validate.js';

describe('validate – min / max', () => {
  test.each([
    ['abc', { min: 4 }, false, ['min']],
    ['abcd', { min: 4 }, true, []],
    ['abcde', { max: 4 }, false, ['max']],
    ['abcd', { max: 4 }, true, []],
    ['ab', { min: 2, max: 5 }, true, []],
  ] as const)(
    'password=%s options=%o → isValid=%s',
    (pw, opts, expectedValid, expectedRules) => {
      const result = validate(pw, opts);
      expect(result.isValid).toBe(expectedValid);
      if (!result.isValid) {
        const ruleNames = result.failedRules.map((r) => r.rule);
        for (const r of expectedRules) expect(ruleNames).toContain(r);
      }
    },
  );
});

describe('validate – character requirements', () => {
  test.each([
    ['abc', { digits: 1 }, false],
    ['abc1', { digits: 1 }, true],
    ['ABC', { lowercase: 1 }, false],
    ['ABCa', { lowercase: 1 }, true],
    ['abc', { uppercase: 1 }, false],
    ['abcA', { uppercase: 1 }, true],
    ['abc', { symbols: 1 }, false],
    ['abc!', { symbols: 1 }, true],
  ] as const)('password=%s → isValid=%s', (pw, opts, expected) => {
    expect(validate(pw, opts).isValid).toBe(expected);
  });
});

describe('validate – spaces', () => {
  test('allows spaces by default', () => {
    expect(validate('hello world').isValid).toBe(true);
  });
  test('rejects spaces when spaces=false', () => {
    const r = validate('hello world', { spaces: false });
    expect(r.isValid).toBe(false);
    if (!r.isValid) expect(r.failedRules[0]!.rule).toBe('spaces');
  });
});

describe('validate – not blocklist (timing-safe)', () => {
  test('rejects exact blocked password', () => {
    const r = validate('password', { not: ['password'] });
    expect(r.isValid).toBe(false);
  });
  test('blocklist is case-insensitive', () => {
    expect(validate('PASSWORD', { not: ['password'] }).isValid).toBe(false);
  });
  test('passes when not in list', () => {
    expect(validate('secureP@ss!', { not: ['password'] }).isValid).toBe(true);
  });
});

describe('validate – regex', () => {
  test('passes when regex matches', () => {
    expect(validate('abc123', { regex: /^[a-z0-9]+$/ }).isValid).toBe(true);
  });
  test('fails when regex does not match', () => {
    const r = validate('abc 123', { regex: /^[a-z0-9]+$/ });
    expect(r.isValid).toBe(false);
    if (!r.isValid) expect(r.failedRules[0]!.rule).toBe('regex');
  });
});

describe('validate – noSequential (bidirectional)', () => {
  test.each([
    ['1234', true],    // ascending numeric
    ['9876', true],    // descending numeric
    ['abcd', true],    // ascending alpha
    ['dcba', true],    // descending alpha
    ['a1b2', false],   // non-sequential
    ['12', false],     // too short to be sequential
    ['123', true],     // exactly 3
  ] as const)('"%s" hasSequential=%s', (pw, hasSeq) => {
    const r = validate(pw, { noSequential: true });
    expect(r.isValid).toBe(!hasSeq);
  });
});

describe('validate – noRepeating', () => {
  test('fails when repeating exceeds limit', () => {
    const r = validate('aaab', { noRepeating: 2 });
    expect(r.isValid).toBe(false);
  });
  test('passes at exactly the limit', () => {
    expect(validate('aab', { noRepeating: 2 }).isValid).toBe(true);
  });
});

describe('validate – custom is() function', () => {
  test('passes when is() returns true', () => {
    expect(validate('ok', { is: () => true }).isValid).toBe(true);
  });
  test('fails when is() returns false', () => {
    const r = validate('no', { is: () => false });
    expect(r.isValid).toBe(false);
    if (!r.isValid) expect(r.failedRules[0]!.message).toBe('Password failed custom validation.');
  });
  test('uses custom message when is() returns string', () => {
    const r = validate('no', { is: () => 'Too simple.' });
    expect(r.isValid).toBe(false);
    if (!r.isValid) expect(r.failedRules[0]!.message).toBe('Too simple.');
  });
});

describe('validate – multiple failed rules', () => {
  test('reports all failed rules', () => {
    const r = validate('a', { min: 8, digits: 1, uppercase: 1 });
    expect(r.isValid).toBe(false);
    if (!r.isValid) {
      const rules = r.failedRules.map((f) => f.rule);
      expect(rules).toContain('min');
      expect(rules).toContain('digits');
      expect(rules).toContain('uppercase');
    }
  });
});

describe('validate – TypeScript discriminated union narrowing', () => {
  test('failedRules type narrows correctly', () => {
    const result: ValidationResult = validate('pass', { min: 8 });
    if (!result.isValid) {
      expectTypeOf(result.failedRules).toEqualTypeOf<Array<{ rule: string; message: string }>>();
    } else {
      expectTypeOf(result.failedRules).toEqualTypeOf<[]>();
    }
  });
});
