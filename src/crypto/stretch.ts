/**
 * @module crypto/stretch
 *
 * PBKDF2 key derivation using the Web Crypto API with
 * OWASP 2024 recommended iteration counts per algorithm.
 *
 * @example
 * ```ts
 * import { pbkdf2Hash } from 'passwordthing/crypto';
 * // Registration: generate random salt
 * const { hash, salt } = await pbkdf2Hash('myPassword');
 * // Login: reproduce hash from stored salt
 * const { hash: loginHash } = await pbkdf2Hash('myPassword', { salt });
 * ```
 */

export type Pbkdf2HashAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512';

const OWASP_ITERATIONS: Record<Pbkdf2HashAlgorithm, number> = {
  'SHA-256': 600_000,
  'SHA-384': 210_000,
  'SHA-512': 210_000,
};

const KEY_LENGTH_BITS = 256;

export interface Pbkdf2HashOptions {
  /** Hex-encoded salt (16 bytes). If omitted, a random salt is generated. */
  salt?: string;
  /** Hash algorithm. Default `'SHA-256'`. */
  hash?: Pbkdf2HashAlgorithm;
  /** Iteration count. Defaults to OWASP 2024 recommendation for chosen hash. */
  iterations?: number;
}

export interface Pbkdf2HashResult {
  /** Base64-encoded 256-bit derived key. */
  hash: string;
  /** Hex-encoded 16-byte salt (store alongside hash). */
  salt: string;
}

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Derives a server-safe key from a password using PBKDF2.
 *
 * For registration: call without `salt`, a random salt is generated and returned.
 * For login:        call with the stored `salt` to reproduce the same hash.
 *
 * Default iterations follow OWASP 2024 recommendations per algorithm:
 *   SHA-256: 600,000  |  SHA-384: 210,000  |  SHA-512: 210,000
 *
 * Store both `hash` and `salt`; never store the plaintext password.
 */
export async function pbkdf2Hash(
  password: string,
  options: Pbkdf2HashOptions = {},
): Promise<Pbkdf2HashResult> {
  const algo = options.hash ?? 'SHA-256';
  const iterations = options.iterations ?? OWASP_ITERATIONS[algo];

  let saltBytes: Uint8Array;
  let saltHex: string;

  if (options.salt !== undefined) {
    saltBytes = hexToBytes(options.salt);
    saltHex = options.salt;
  } else {
    saltBytes = new Uint8Array(16);
    globalThis.crypto.getRandomValues(saltBytes as Uint8Array<ArrayBuffer>);
    saltHex = bytesToHex(saltBytes);
  }

  const enc = new TextEncoder();
  const keyMaterial = await globalThis.crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveBits'],
  );

  const derivedBuffer = await globalThis.crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: algo,
      salt: saltBytes.buffer as ArrayBuffer,
      iterations,
    },
    keyMaterial,
    KEY_LENGTH_BITS,
  );

  const derivedBytes = new Uint8Array(derivedBuffer);
  let _binary = '';
  for (let _i = 0; _i < derivedBytes.length; _i++) _binary += String.fromCharCode(derivedBytes[_i]!);
  const hash = btoa(_binary);

  // Zero-fill derived bytes from memory
  derivedBytes.fill(0);

  return { hash, salt: saltHex };
}
