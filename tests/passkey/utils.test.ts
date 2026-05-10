import { describe, expect, test } from 'vitest';
import { base64URLToArrayBuffer, arrayBufferToBase64URL } from '../../src/passkey/utils.js';

describe('base64URLToArrayBuffer – decoding', () => {
  test('decodes known base64url value', () => {
    // "Hello" in base64 = "SGVsbG8=", base64url = "SGVsbG8"
    const buffer = base64URLToArrayBuffer('SGVsbG8');
    const bytes = new Uint8Array(buffer);
    expect(bytes).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
  });

  test('handles padding variants', () => {
    // base64url without padding
    const buf1 = base64URLToArrayBuffer('YQ');   // "a"
    expect(new Uint8Array(buf1)[0]).toBe(97);
  });
});

describe('arrayBufferToBase64URL – encoding', () => {
  test('encodes known bytes', () => {
    const bytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
    expect(arrayBufferToBase64URL(bytes.buffer)).toBe('SGVsbG8');
  });

  test('no padding characters in output', () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const result = arrayBufferToBase64URL(bytes.buffer);
    expect(result).not.toContain('=');
  });

  test('uses URL-safe chars (no + or /)', () => {
    // Use bytes that would produce + or / in standard base64
    const bytes = new Uint8Array([0xfb, 0xff, 0xfe]);
    const result = arrayBufferToBase64URL(bytes.buffer);
    expect(result).not.toContain('+');
    expect(result).not.toContain('/');
  });
});

describe('round-trip fidelity', () => {
  test('encode → decode round-trip', () => {
    const original = new Uint8Array([1, 2, 3, 4, 5, 100, 200, 255, 0]);
    const encoded = arrayBufferToBase64URL(original.buffer);
    const decoded = new Uint8Array(base64URLToArrayBuffer(encoded));
    expect(decoded).toEqual(original);
  });

  test('random 32-byte round-trip', () => {
    const original = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const encoded = arrayBufferToBase64URL(original.buffer);
    const decoded = new Uint8Array(base64URLToArrayBuffer(encoded));
    expect(decoded).toEqual(original);
  });
});
