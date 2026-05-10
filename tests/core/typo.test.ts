import { describe, expect, test } from 'vitest';
import { checkTypo } from '../../src/core/typo.js';

describe('checkTypo – known distance matrix', () => {
  test.each([
    // [a, b, expectedDistance, expectedMatch, expectedMessage]
    ['', '', 0, true, 'Match'],
    ['abc', 'abc', 0, true, 'Match'],
    ['abc', 'abcd', 1, false, '1 character off'],
    ['abc', 'abd', 1, false, '1 character off'],
    ['abc', 'xyz', 3, false, 'Significantly different'],
    ['kitten', 'sitting', 3, false, 'Significantly different'],
    ['Sunday', 'Saturday', 3, false, 'Significantly different'],
    ['', 'abc', 3, false, 'Significantly different'],
    ['abc', '', 3, false, 'Significantly different'],
    ['password', 'passwrd', 1, false, '1 character off'],
    ['password', 'password', 0, true, 'Match'],
  ] as const)('"%s" vs "%s" → distance=%d match=%s', (a, b, dist, match, msg) => {
    const result = checkTypo(a, b);
    expect(result.distance).toBe(dist);
    expect(result.match).toBe(match);
    expect(result.message).toBe(msg);
  });
});

describe('checkTypo – symmetry', () => {
  test('distance is symmetric', () => {
    expect(checkTypo('abc', 'xyz').distance).toBe(checkTypo('xyz', 'abc').distance);
  });
});

describe('checkTypo – unicode handling', () => {
  test('handles unicode characters', () => {
    const r = checkTypo('héllo', 'hello');
    expect(r.distance).toBeGreaterThan(0);
  });
});
