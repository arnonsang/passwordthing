import { hotp, type HMACAlgorithm } from './hotp.js';
import { base32Encode } from './base32.js';

export interface TOTPOptions {
  digits?: 6 | 8;
  period?: number;
  algorithm?: HMACAlgorithm;
  window?: number;
}

export interface OTPAuthURLOptions {
  secret: string;
  issuer: string;
  account: string;
  algorithm?: HMACAlgorithm;
  digits?: 6 | 8;
  period?: number;
}

export function generateSecret(): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  return base32Encode(bytes);
}

export async function generateTOTP(secret: string, options: TOTPOptions = {}): Promise<string> {
  const { digits = 6, period = 30, algorithm = 'SHA-1' } = options;
  const counter = Math.floor(Date.now() / 1000 / period);
  return hotp(secret, counter, digits, algorithm);
}

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
