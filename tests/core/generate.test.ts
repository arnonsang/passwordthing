import { describe, expect, test } from 'vitest';
import * as fc from 'fast-check';
import { generate } from '../../src/core/generate.js';

const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*()_+~|}{[]:;?><,./-=';
const AMBIGUOUS = new Set(['i', 'l', '1', 'L', 'o', '0', 'O', 'I']);

function charsIn(str: string, pool: string): boolean {
  return [...str].every((c) => pool.includes(c));
}

describe('generate – output length', () => {
  test('property: length always matches requested length (non-pronounceable)', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 128 }),
        (len) => {
          const pw = generate({ length: len });
          return pw.length === len;
        },
      ),
    );
  });

  test('pronounceable: total length = length (extras included)', () => {
    // With digits+symbols appended, the pronounceable core shrinks to fit
    const pw = generate({ length: 12, pronounceable: true, includeDigits: true, includeSymbols: true });
    expect(pw.length).toBe(12);
  });
});

describe('generate – character pool constraints', () => {
  test('uppercase only', () => {
    fc.assert(
      fc.property(fc.integer({ min: 1, max: 32 }), (len) => {
        const pw = generate({ length: len, includeUppercase: true, includeLowercase: false, includeDigits: false });
        return charsIn(pw, UPPERCASE);
      }),
    );
  });

  test('lowercase only', () => {
    fc.assert(
      fc.property(fc.integer({ min: 1, max: 32 }), (len) => {
        const pw = generate({ length: len, includeUppercase: false, includeLowercase: true, includeDigits: false });
        return charsIn(pw, LOWERCASE);
      }),
    );
  });

  test('digits only', () => {
    fc.assert(
      fc.property(fc.integer({ min: 1, max: 32 }), (len) => {
        const pw = generate({ length: len, includeUppercase: false, includeLowercase: false, includeDigits: true });
        return charsIn(pw, DIGITS);
      }),
    );
  });

  test('symbols included – all chars in allowed pool', () => {
    const allChars = UPPERCASE + LOWERCASE + DIGITS + SYMBOLS;
    fc.assert(
      fc.property(fc.integer({ min: 4, max: 32 }), (len) => {
        const pw = generate({ length: len, includeSymbols: true });
        return charsIn(pw, allChars);
      }),
    );
  });
});

describe('generate – excludeAmbiguous', () => {
  test('no ambiguous characters when excludeAmbiguous=true', () => {
    fc.assert(
      fc.property(fc.integer({ min: 4, max: 64 }), (len) => {
        const pw = generate({ length: len, excludeAmbiguous: true });
        return ![...pw].some((c) => AMBIGUOUS.has(c));
      }),
    );
  });
});

describe('generate – customCharset', () => {
  test('uses only custom charset', () => {
    const charset = 'abc';
    fc.assert(
      fc.property(fc.integer({ min: 1, max: 32 }), (len) => {
        const pw = generate({ length: len, customCharset: charset });
        return pw.length === len && charsIn(pw, charset);
      }),
    );
  });

  test('throws on empty customCharset', () => {
    expect(() => generate({ length: 8, customCharset: '' })).toThrow();
  });
});

describe('generate – pronounceable', () => {
  test('alphabetic characters present in base portion', () => {
    const pw = generate({ length: 10, pronounceable: true, includeDigits: false, includeSymbols: false });
    expect(pw.length).toBe(10);
    expect(charsIn(pw, LOWERCASE)).toBe(true);
  });

  test('digit appended when includeDigits=true', () => {
    const results = Array.from({ length: 20 }, () =>
      generate({ length: 4, pronounceable: true, includeDigits: true, includeSymbols: false }),
    );
    // Last character should be a digit
    expect(results.every((pw) => DIGITS.includes(pw.at(-1)!))).toBe(true);
  });
});

describe('generate – error handling', () => {
  test('throws on length < 1', () => {
    expect(() => generate({ length: 0 })).toThrow(RangeError);
  });
  test('throws when no pool selected', () => {
    expect(() =>
      generate({ length: 8, includeUppercase: false, includeLowercase: false, includeDigits: false }),
    ).toThrow();
  });
});
