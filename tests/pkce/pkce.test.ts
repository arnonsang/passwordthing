import { describe, expect, test } from 'vitest';
import { generateCodeVerifier, generateCodeChallenge } from '../../src/pkce/pkce.js';

describe('generateCodeVerifier', () => {
  test('default length is 64 chars', () => {
    const v = generateCodeVerifier();
    expect(v).toHaveLength(64);
  });

  test('only base64url characters', () => {
    const v = generateCodeVerifier();
    expect(/^[A-Za-z0-9\-_]+$/.test(v)).toBe(true);
  });

  test('respects custom length', () => {
    expect(generateCodeVerifier(43)).toHaveLength(43);
    expect(generateCodeVerifier(128)).toHaveLength(128);
  });

  test('throws on out-of-range length', () => {
    expect(() => generateCodeVerifier(42)).toThrow();
    expect(() => generateCodeVerifier(129)).toThrow();
  });

  test('generates unique values', () => {
    expect(generateCodeVerifier()).not.toBe(generateCodeVerifier());
  });
});

describe('generateCodeChallenge', () => {
  // RFC 7636 Appendix B test vector
  test('RFC 7636 test vector', async () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const challenge = await generateCodeChallenge(verifier);
    expect(challenge).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  test('returns base64url string (no +, /, =)', async () => {
    const challenge = await generateCodeChallenge(generateCodeVerifier());
    expect(challenge).not.toContain('+');
    expect(challenge).not.toContain('/');
    expect(challenge).not.toContain('=');
  });

  test('same verifier produces same challenge', async () => {
    const v = generateCodeVerifier();
    expect(await generateCodeChallenge(v)).toBe(await generateCodeChallenge(v));
  });
});
