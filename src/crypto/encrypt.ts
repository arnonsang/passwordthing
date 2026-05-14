/**
 * @module crypto/encrypt
 *
 * AES-256-GCM authenticated encryption with PBKDF2 key derivation.
 * Suitable for client-side vault storage. Each call generates a fresh
 * random salt and IV, so the same password produces different ciphertext.
 *
 * @example
 * ```ts
 * import { encrypt, decrypt } from 'passwordthing/crypto';
 *
 * const data = await encrypt('secret text', 'my-vault-password');
 * const plain = await decrypt(data, 'my-vault-password');
 * // plain === 'secret text'
 * ```
 */

export type EncryptHashAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512';

const OWASP_ITERATIONS: Record<EncryptHashAlgorithm, number> = {
  'SHA-256': 600_000,
  'SHA-384': 210_000,
  'SHA-512': 210_000,
};

export interface EncryptOptions {
  /** PBKDF2 iteration count. Defaults to OWASP 2024 recommendation for chosen hash. */
  iterations?: number;
  /** PBKDF2 hash algorithm. Default `'SHA-256'`. */
  hash?: EncryptHashAlgorithm;
}

export interface EncryptedData {
  /** Base64-encoded AES-GCM ciphertext (includes authentication tag). */
  ciphertext: string;
  /** Hex-encoded 12-byte AES-GCM IV. */
  iv: string;
  /** Hex-encoded 16-byte PBKDF2 salt. */
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

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function deriveKey(
  password: string,
  salt: Uint8Array,
  algo: EncryptHashAlgorithm,
  iterations: number,
  usage: KeyUsage[],
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await globalThis.crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return globalThis.crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: algo, salt: salt.buffer as ArrayBuffer, iterations },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    usage,
  );
}

/**
 * Encrypts a UTF-8 string with AES-256-GCM, deriving the key via PBKDF2.
 *
 * A random 16-byte salt and 12-byte IV are generated per call.
 * Store the returned `EncryptedData` object alongside your encrypted content.
 *
 * @param plaintext - The string to encrypt.
 * @param password - The password to derive the encryption key from.
 * @param options - Optional PBKDF2 parameters.
 * @returns Encrypted data with ciphertext, IV, and salt.
 *
 * @example
 * ```ts
 * const vault = await encrypt(JSON.stringify(passwords), masterPassword);
 * localStorage.setItem('vault', JSON.stringify(vault));
 * ```
 */
export async function encrypt(
  plaintext: string,
  password: string,
  options: EncryptOptions = {},
): Promise<EncryptedData> {
  const algo = options.hash ?? 'SHA-256';
  const iterations = options.iterations ?? OWASP_ITERATIONS[algo];

  const salt = new Uint8Array(16);
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(salt as Uint8Array<ArrayBuffer>);
  globalThis.crypto.getRandomValues(iv as Uint8Array<ArrayBuffer>);

  const key = await deriveKey(password, salt, algo, iterations, ['encrypt']);

  const enc = new TextEncoder();
  const ciphertextBuffer = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
    key,
    enc.encode(plaintext),
  );

  return {
    ciphertext: bytesToBase64(new Uint8Array(ciphertextBuffer)),
    iv: bytesToHex(iv),
    salt: bytesToHex(salt),
  };
}

/**
 * Decrypts data produced by `encrypt`.
 *
 * @param data - The `EncryptedData` object returned by `encrypt`.
 * @param password - The same password used during encryption.
 * @param options - Must match the PBKDF2 parameters used during encryption.
 * @returns Decrypted plaintext string.
 *
 * @throws {DOMException} If the password is wrong or data is tampered (authentication failure).
 *
 * @example
 * ```ts
 * const stored = JSON.parse(localStorage.getItem('vault')!);
 * const plain = await decrypt(stored, masterPassword);
 * ```
 */
export async function decrypt(
  data: EncryptedData,
  password: string,
  options: EncryptOptions = {},
): Promise<string> {
  const algo = options.hash ?? 'SHA-256';
  const iterations = options.iterations ?? OWASP_ITERATIONS[algo];

  const salt = hexToBytes(data.salt);
  const iv = hexToBytes(data.iv);
  const ciphertext = base64ToBytes(data.ciphertext);

  const key = await deriveKey(password, salt, algo, iterations, ['decrypt']);

  const plaintextBuffer = await globalThis.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
    key,
    ciphertext.buffer as ArrayBuffer,
  );

  return new TextDecoder().decode(plaintextBuffer);
}
