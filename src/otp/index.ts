/**
 * @module otp
 *
 * HMAC-based One-Time Password (HOTP, RFC 4226) and
 * Time-based One-Time Password (TOTP, RFC 6238) with
 * base32 secret encoding and OTP auth URL generation.
 *
 * @example
 * ```ts
 * import { generateSecret, generateTOTP, verifyTOTP } from 'passwordthing/otp';
 * const secret = generateSecret();
 * const token = await generateTOTP(secret);
 * const valid = await verifyTOTP(secret, token);
 * ```
 */

export { base32Encode, base32Decode } from './base32.js';
export { hotp } from './hotp.js';
export type { HMACAlgorithm } from './hotp.js';
export { generateSecret, generateTOTP, verifyTOTP, generateOTPAuthURL } from './totp.js';
export type { TOTPOptions, OTPAuthURLOptions } from './totp.js';
