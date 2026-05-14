/**
 * @module otp/hotp
 *
 * HMAC-based One-Time Password (RFC 4226). Computes a
 * truncated HMAC over a 64-bit big-endian counter value.
 *
 * @example
 * ```ts
 * import { hotp } from 'passwordthing/otp';
 * const token = await hotp('JBSWY3DPEHPK3PXP', 0);
 * ```
 */

import { base32Decode } from './base32.js';

/** Supported HMAC hash algorithms for HOTP/TOTP. */
export type HMACAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-512';

/**
 * Generate an HOTP token.
 *
 * @param secret - Base32-encoded shared secret.
 * @param counter - 64-bit counter value.
 * @param digits - Number of digits in the token (6 or 8). Default 6.
 * @param algorithm - HMAC hash algorithm. Default `'SHA-1'`.
 * @returns Zero-padded OTP string.
 */
export async function hotp(
  secret: string,
  counter: number,
  digits: 6 | 8 = 6,
  algorithm: HMACAlgorithm = 'SHA-1',
): Promise<string> {
  const keyBytes = base32Decode(secret);
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes as Uint8Array<ArrayBuffer>,
    { name: 'HMAC', hash: algorithm },
    false,
    ['sign'],
  );

  const counterBuffer = new ArrayBuffer(8);
  const view = new DataView(counterBuffer);
  // Write 64-bit big-endian counter
  view.setUint32(0, Math.floor(counter / 0x100000000), false);
  view.setUint32(4, counter >>> 0, false);

  const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBuffer));

  const offset = hmac[hmac.length - 1]! & 0x0f;
  const code =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff);

  return String(code % 10 ** digits).padStart(digits, '0');
}
