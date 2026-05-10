import { describe, expect, test } from 'vitest';
import { evaluateStrength } from '../../src/strength/entropy.js';


const CASES = [
  // [password, minScore, maxScore]
  ['', 0, 0],
  ['a', 0, 0],
  ['123456', 0, 1],
  ['password', 0, 1],
  ['password1', 0, 1],
  ['qwerty', 0, 1],
  ['abc123', 0, 1],
  ['iloveyou', 0, 1],
  ['P@ssw0rd', 0, 2],    // l33t of common password → weak
  ['letmein123!', 1, 3],
  ['correcthorsebatterystaple', 3, 4],
  ['Tr0ub4dor&3', 2, 4],
  ['$uper$ecretPa$$word!99', 3, 4],
  ['aB3!aB3!aB3!aB3!aB3!', 3, 4],
] as const;

describe('evaluateStrength – score range', () => {
  test.each(CASES)('"%s" score in [%d, %d]', (pw, min, max) => {
    const result = evaluateStrength(pw);
    expect(result.score).toBeGreaterThanOrEqual(min);
    expect(result.score).toBeLessThanOrEqual(max);
  });
});

describe('evaluateStrength – output shape', () => {
  test('returns required fields', () => {
    const r = evaluateStrength('SomePassword99!');
    expect(typeof r.entropyBits).toBe('number');
    expect(['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong']).toContain(r.label);
    expect(typeof r.timeToCrack.offlineFastHashing).toBe('string');
    expect(typeof r.timeToCrack.onlineThrottled).toBe('string');
    expect(r.feedback).toBeDefined();
  });

  test('empty password returns score 0', () => {
    const r = evaluateStrength('');
    expect(r.score).toBe(0);
    expect(r.entropyBits).toBe(0);
  });
});

describe('evaluateStrength – presets', () => {
  test('OWASP_STRICT gives lower score for same password', () => {
    const pw = 'Summer2024!';
    const basic = evaluateStrength(pw, { preset: 'BASIC' });
    const owasp = evaluateStrength(pw, { preset: 'OWASP_STRICT' });
    expect(owasp.score).toBeLessThanOrEqual(basic.score);
  });

  test('NIST_MODERN is more lenient', () => {
    const pw = 'correcthorse';
    const nist = evaluateStrength(pw, { preset: 'NIST_MODERN' });
    expect(nist.score).toBeGreaterThanOrEqual(2);
  });
});

describe('evaluateStrength – userInputs penalty', () => {
  test('password containing user name scores lower', () => {
    const without = evaluateStrength('alice12345!!');
    const withInput = evaluateStrength('alice12345!!', { userInputs: ['alice'] });
    expect(withInput.score).toBeLessThanOrEqual(without.score);
  });
});

describe('evaluateStrength – stronger password scores higher', () => {
  test('longer password scores higher than shorter', () => {
    const short = evaluateStrength('Ab1!');
    const long = evaluateStrength('Ab1!Ab1!Ab1!Ab1!Ab1!Ab1!');
    expect(long.score).toBeGreaterThanOrEqual(short.score);
  });
});

describe('evaluateStrength – timeToCrack format', () => {
  test('very weak password cracks instantly offline', () => {
    const r = evaluateStrength('a');
    expect(r.timeToCrack.offlineFastHashing).toMatch(/second/);
  });

  test('strong password takes much longer online', () => {
    const r = evaluateStrength('correct-horse-battery-staple-99!');
    const online = r.timeToCrack.onlineThrottled;
    expect(online).toMatch(/year|centur|million|billion/i);
  });
});
