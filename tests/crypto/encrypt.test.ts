import { describe, expect, test } from 'vitest';
import { encrypt, decrypt } from '../../src/crypto/encrypt.js';

describe('encrypt / decrypt – round-trip', () => {
  test('decrypts to original plaintext', async () => {
    const plain = 'hello, world!';
    const data = await encrypt(plain, 'secret');
    expect(await decrypt(data, 'secret')).toBe(plain);
  });

  test('round-trips empty string', async () => {
    const data = await encrypt('', 'pass');
    expect(await decrypt(data, 'pass')).toBe('');
  });

  test('round-trips unicode / emoji', async () => {
    const plain = 'こんにちは 🔐 café';
    const data = await encrypt(plain, 'pw');
    expect(await decrypt(data, 'pw')).toBe(plain);
  });
});

describe('encrypt – output shape', () => {
  test('returns ciphertext, iv, salt fields', async () => {
    const data = await encrypt('test', 'pw');
    expect(typeof data.ciphertext).toBe('string');
    expect(typeof data.iv).toBe('string');
    expect(typeof data.salt).toBe('string');
  });

  test('iv is 24-char hex (12 bytes)', async () => {
    const { iv } = await encrypt('x', 'pw');
    expect(iv).toMatch(/^[0-9a-f]{24}$/);
  });

  test('salt is 32-char hex (16 bytes)', async () => {
    const { salt } = await encrypt('x', 'pw');
    expect(salt).toMatch(/^[0-9a-f]{32}$/);
  });

  test('produces different ciphertext each call (fresh random salt+iv)', async () => {
    const a = await encrypt('same', 'pw');
    const b = await encrypt('same', 'pw');
    expect(a.ciphertext).not.toBe(b.ciphertext);
    expect(a.iv).not.toBe(b.iv);
    expect(a.salt).not.toBe(b.salt);
  });
});

describe('decrypt – error handling', () => {
  test('throws on wrong password', async () => {
    const data = await encrypt('secret', 'correct');
    await expect(decrypt(data, 'wrong')).rejects.toThrow();
  });

  test('throws on tampered ciphertext', async () => {
    const data = await encrypt('secret', 'pass');
    const tampered = { ...data, ciphertext: data.ciphertext.slice(0, -2) + 'XX' };
    await expect(decrypt(tampered, 'pass')).rejects.toThrow();
  });
});

describe('encrypt – hash algorithm options', () => {
  test('SHA-384 round-trips correctly', async () => {
    const plain = 'SHA-384 test';
    const data = await encrypt(plain, 'pw', { hash: 'SHA-384' });
    expect(await decrypt(data, 'pw', { hash: 'SHA-384' })).toBe(plain);
  });

  test('SHA-512 round-trips correctly', async () => {
    const plain = 'SHA-512 test';
    const data = await encrypt(plain, 'pw', { hash: 'SHA-512' });
    expect(await decrypt(data, 'pw', { hash: 'SHA-512' })).toBe(plain);
  });

  test('custom iteration count', async () => {
    const plain = 'low iter test';
    const data = await encrypt(plain, 'pw', { iterations: 1000 });
    expect(await decrypt(data, 'pw', { iterations: 1000 })).toBe(plain);
  });
});
