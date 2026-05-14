/**
 * @module crypto
 *
 * Cryptographic primitives: PBKDF2 password hashing and
 * SRP (Secure Remote Password) protocol for zero-knowledge
 * password-based authentication.
 *
 * @example
 * ```ts
 * import { pbkdf2Hash } from 'passwordthing/crypto';
 * const { hash, salt } = await pbkdf2Hash('myPassword');
 * ```
 */

export type { SRPRegistration, SRPProof } from './srp.js';
export { createSRPRegistration, createSRPProof } from './srp.js';

export type { Pbkdf2HashAlgorithm, Pbkdf2HashOptions, Pbkdf2HashResult } from './stretch.js';
export { pbkdf2Hash } from './stretch.js';

export type { EncryptOptions, EncryptedData, EncryptHashAlgorithm } from './encrypt.js';
export { encrypt, decrypt } from './encrypt.js';
