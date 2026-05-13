import { describe, expect, test } from 'vitest';
import { hotp } from '../../src/otp/hotp.js';
import { base32Encode, base32Decode } from '../../src/otp/base32.js';

// RFC 4226 test vectors (Appendix D), secret = "12345678901234567890" in ASCII
const RFC_SECRET_BYTES = new TextEncoder().encode('12345678901234567890');
const RFC_SECRET = base32Encode(RFC_SECRET_BYTES);

const RFC_VECTORS: [number, string][] = [
  [0, '755224'],
  [1, '287082'],
  [2, '359152'],
  [3, '969429'],
  [4, '338314'],
  [5, '254676'],
  [6, '287922'],
  [7, '162583'],
  [8, '399871'],
  [9, '520489'],
];

describe('base32', () => {
  test('roundtrip encode/decode', () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5, 100, 200, 255]);
    expect(base32Decode(base32Encode(bytes))).toEqual(bytes);
  });

  test('decode is case-insensitive', () => {
    const encoded = base32Encode(new Uint8Array([0xde, 0xad, 0xbe]));
    expect(base32Decode(encoded.toLowerCase())).toEqual(base32Decode(encoded));
  });

  test('throws on invalid character', () => {
    expect(() => base32Decode('INVALID1')).toThrow('Invalid base32 character');
  });
});

describe('hotp', () => {
  test.each(RFC_VECTORS)('RFC 4226 vector counter=%i → %s', async (counter, expected) => {
    const result = await hotp(RFC_SECRET, counter);
    expect(result).toBe(expected);
  });

  test('8-digit output', async () => {
    const code = await hotp(RFC_SECRET, 0, 8);
    expect(code).toHaveLength(8);
  });

  test('output is zero-padded to digits length', async () => {
    const code = await hotp(RFC_SECRET, 0, 6);
    expect(code).toHaveLength(6);
    expect(/^\d+$/.test(code)).toBe(true);
  });
});
