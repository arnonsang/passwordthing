/**
 * @module otp/base32
 *
 * RFC 4648 base32 encoding/decoding using the
 * A-Z + 2-7 alphabet (no padding).
 *
 * @example
 * ```ts
 * import { base32Encode, base32Decode } from 'passwordthing/otp';
 * ```
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Encode bytes to a base32 string.
 *
 * @param bytes - Input bytes.
 * @returns Base32-encoded string.
 */
export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i]!;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += ALPHABET[(value >>> bits) & 0x1f];
    }
  }
  if (bits > 0) {
    output += ALPHABET[(value << (5 - bits)) & 0x1f];
  }
  return output;
}

/**
 * Decode a base32 string to bytes.
 *
 * @param input - Base32-encoded string (case-insensitive, padding optional).
 * @returns Decoded Uint8Array.
 * @throws {Error} If the input contains an invalid character.
 */
export function base32Decode(input: string): Uint8Array {
  const str = input.toUpperCase().replace(/=+$/, '');
  const bytes = new Uint8Array(Math.floor((str.length * 5) / 8));
  let bits = 0;
  let value = 0;
  let index = 0;
  for (let i = 0; i < str.length; i++) {
    const idx = ALPHABET.indexOf(str[i]!);
    if (idx === -1) throw new Error(`Invalid base32 character: ${str[i]}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes[index++] = (value >>> bits) & 0xff;
    }
  }
  return bytes;
}
