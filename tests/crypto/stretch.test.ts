import { describe, expect, test } from 'vitest';
import { pbkdf2Hash } from '../../src/crypto/stretch.js';

describe('pbkdf2Hash – output shape', () => {
  test('returns a hash and salt', async () => {
    const result = await pbkdf2Hash('password');
    expect(typeof result.hash).toBe('string');
    expect(result.hash.length).toBeGreaterThan(0);
    expect(typeof result.salt).toBe('string');
    expect(result.salt.length).toBe(32); // 16 bytes -> 32 hex chars
  });

  test('hash is base64-encoded', async () => {
    const { hash } = await pbkdf2Hash('password');
    // Valid base64 pattern
    expect(() => atob(hash)).not.toThrow();
    // 256-bit key = 32 bytes = 44 chars in base64 (with padding)
    expect(hash.length).toBe(44);
  });
});

describe('pbkdf2Hash – determinism with provided salt', () => {
  test('same password + salt -> same hash', async () => {
    const first = await pbkdf2Hash('mypassword');
    const second = await pbkdf2Hash('mypassword', { salt: first.salt });
    expect(second.hash).toBe(first.hash);
  });

  test('different password, same salt -> different hash', async () => {
    const first = await pbkdf2Hash('password1');
    const second = await pbkdf2Hash('password2', { salt: first.salt });
    expect(second.hash).not.toBe(first.hash);
  });

  test('same password, different salt -> different hash', async () => {
    const first = await pbkdf2Hash('samepass');
    const second = await pbkdf2Hash('samepass');
    // Different salts -> different hashes (probabilistically)
    expect(first.salt).not.toBe(second.salt);
    expect(first.hash).not.toBe(second.hash);
  });
});

describe('pbkdf2Hash – custom iterations', () => {
  test('custom iterations still produces valid output', async () => {
    const result = await pbkdf2Hash('pwd', { iterations: 1_000 });
    expect(result.hash.length).toBe(44);
  });

  test('different iterations -> different hash (same salt)', async () => {
    const base = await pbkdf2Hash('test');
    const custom = await pbkdf2Hash('test', { salt: base.salt, iterations: 1_000 });
    expect(custom.hash).not.toBe(base.hash);
  });
});

describe('pbkdf2Hash – hash algorithm option', () => {
  test('SHA-384 produces valid base64 output', async () => {
    const result = await pbkdf2Hash('pwd', { hash: 'SHA-384', iterations: 1_000 });
    expect(() => atob(result.hash)).not.toThrow();
    expect(result.hash.length).toBe(44); // KEY_LENGTH_BITS is always 256 -> 44 chars
  });

  test('SHA-512 produces valid base64 output', async () => {
    const result = await pbkdf2Hash('pwd', { hash: 'SHA-512', iterations: 1_000 });
    expect(() => atob(result.hash)).not.toThrow();
    expect(result.hash.length).toBe(44);
  });

  test('same password + salt with different hash -> different output', async () => {
    const base = await pbkdf2Hash('test', { iterations: 1_000 }); // SHA-256
    const sha512 = await pbkdf2Hash('test', { salt: base.salt, hash: 'SHA-512', iterations: 1_000 });
    expect(sha512.hash).not.toBe(base.hash);
  });
});
