/**
 * @module otp/totp
 *
 * Time-based One-Time Password (RFC 6238). Uses HOTP with
 * `counter = floor(now / period)` and supports configurable
 * time-drift windows for verification. Also provides OTP
 * auth URL generation for QR code provisioning.
 *
 * @example
 * ```ts
 * import { generateSecret, generateTOTP, verifyTOTP, generateOTPAuthURL } from 'passwordthing/otp';
 * ```
 */

import { hotp, type HMACAlgorithm } from './hotp.js';
import { base32Encode } from './base32.js';

export interface TOTPOptions {
  /** Number of digits in the token (6 or 8). Default 6. */
  digits?: 6 | 8;
  /** Time period in seconds. Default 30. */
  period?: number;
  /** HMAC hash algorithm. Default `'SHA-1'`. */
  algorithm?: HMACAlgorithm;
  /** Allowed time-step drift for verification (±N periods). Default 1. */
  window?: number;
}

export interface OTPAuthURLOptions {
  /** Base32-encoded shared secret. */
  secret: string;
  /** Issuer name (e.g. 'MyApp'). */
  issuer: string;
  /** Account identifier (e.g. 'user@example.com'). */
  account: string;
  /** HMAC hash algorithm. Default `'SHA-1'`. */
  algorithm?: HMACAlgorithm;
  /** Number of digits. Default 6. */
  digits?: 6 | 8;
  /** Time period in seconds. Default 30. */
  period?: number;
}

/**
 * Generate a cryptographically random 20-byte secret, base32-encoded.
 *
 * @returns Base32-encoded secret string.
 */
export function generateSecret(): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  return base32Encode(bytes);
}

/**
 * Generate a TOTP token for the current time step.
 *
 * @param secret - Base32-encoded shared secret.
 * @param options - Token options.
 * @returns Zero-padded token string.
 */
export async function generateTOTP(secret: string, options: TOTPOptions = {}): Promise<string> {
  const { digits = 6, period = 30, algorithm = 'SHA-1' } = options;
  const counter = Math.floor(Date.now() / 1000 / period);
  return hotp(secret, counter, digits, algorithm);
}

/**
 * Verify a TOTP token against the current time with a drift window.
 *
 * @param secret - Base32-encoded shared secret.
 * @param token - The token to verify.
 * @param options - Token options (window controls drift tolerance).
 * @returns `true` if the token is valid within the drift window.
 */
export async function verifyTOTP(
  secret: string,
  token: string,
  options: TOTPOptions = {},
): Promise<boolean> {
  const { digits = 6, period = 30, algorithm = 'SHA-1', window: drift = 1 } = options;
  const counter = Math.floor(Date.now() / 1000 / period);
  for (let i = -drift; i <= drift; i++) {
    const expected = await hotp(secret, counter + i, digits, algorithm);
    if (expected === token) return true;
  }
  return false;
}

/**
 * Generate an `otpauth://` URL for QR code provisioning.
 *
 * @param options - URL options (secret, issuer, account).
 * @returns Standard `otpauth://totp/...` URL string.
 */
export function generateOTPAuthURL(options: OTPAuthURLOptions): string {
  const {
    secret,
    issuer,
    account,
    algorithm = 'SHA-1',
    digits = 6,
    period = 30,
  } = options;
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: algorithm.replace('-', ''),
    digits: String(digits),
    period: String(period),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}
