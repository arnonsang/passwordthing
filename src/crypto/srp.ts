/**
 * @module crypto/srp
 *
 * SRP (Secure Remote Password) protocol implementation using
 * 2048-bit MODP group (RFC 5054/RFC 3526) and SHA-256 hashing.
 *
 * Provides client-side zero-knowledge password proof generation
 * without transmitting the password to the server.
 *
 * @example
 * ```ts
 * import { createSRPRegistration, createSRPProof } from 'passwordthing/crypto';
 *
 * // Registration
 * const { salt, verifier } = await createSRPRegistration('alice', 'password123');
 * // Send { salt, verifier } to server, discard password
 *
 * // Authentication
 * const { A, M1 } = await createSRPProof('alice', 'password123', salt, serverB);
 * // Send { A, M1 } to server
 * ```
 */

// RFC 5054 / RFC 3526 – 2048-bit MODP Group
// Using SHA-256 for hashing (more secure than the original SHA-1)

const N_HEX =
  'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
  '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
  'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
  'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
  'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
  'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
  '83655D23DCA3AD961C62F356208552BB9ED52907709696' +
  '6D670C354E4ABC9804F1746C08CA18217C32905E462E36' +
  'CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F' +
  '4C52C9DE2BCBF6955817183995497CEA956AE515D22618' +
  '98FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF';

const N = BigInt('0x' + N_HEX);
const g = 2n;
// N byte length for padding
const N_LEN = Math.ceil(N_HEX.length / 2);

const subtle = (): SubtleCrypto => globalThis.crypto.subtle;

async function H(...parts: Uint8Array[]): Promise<Uint8Array> {
  const total = parts.reduce((s, p) => s + p.byteLength, 0);
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    combined.set(part, offset);
    offset += part.byteLength;
  }
  const digest = await subtle().digest('SHA-256', combined);
  return new Uint8Array(digest);
}

function bigintToBytes(n: bigint, length: number): Uint8Array {
  const hex = n.toString(16).padStart(length * 2, '0');
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToBigint(bytes: Uint8Array): bigint {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return BigInt('0x' + hex);
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

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) result[i] = a[i]! ^ b[i]!;
  return result;
}

/** Modular exponentiation using BigInt */
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

let _k: bigint | null = null;

async function getK(): Promise<bigint> {
  if (_k !== null) return _k;
  const nBytes = bigintToBytes(N, N_LEN);
  const gBytes = bigintToBytes(g, N_LEN);
  const kHash = await H(nBytes, gBytes);
  _k = bytesToBigint(kHash);
  return _k;
}

async function computeX(salt: Uint8Array, identity: string, password: string): Promise<bigint> {
  const enc = new TextEncoder();
  const innerHash = await H(enc.encode(identity + ':' + password));
  const xHash = await H(salt, innerHash);
  return bytesToBigint(xHash);
}

/** SRP registration values for server-side storage. */
export interface SRPRegistration {
  /** Hex-encoded random 16-byte salt. */
  salt: string;
  /** Hex-encoded verifier `v = g^x mod N`. */
  verifier: string;
}

/** SRP client authentication proof. */
export interface SRPProof {
  /** Hex-encoded client public ephemeral value `A`. */
  A: string;
  /** Hex-encoded client proof `M1`. */
  M1: string;
}

/**
 * Creates SRP registration values from identity and password.
 * Send `salt` and `verifier` to the server to store, never send the password.
 */
export async function createSRPRegistration(
  identity: string,
  password: string,
): Promise<SRPRegistration> {
  const salt = randomBytes(16);
  const x = await computeX(salt, identity, password);
  const v = modPow(g, x, N);



  return {
    salt: bytesToHex(salt),
    verifier: v.toString(16).padStart(N_LEN * 2, '0'),
  };
}

/**
 * Computes the SRP client proof.
 * Send `A` and `M1` to the server to authenticate.
 *
 * @param serverSalt  - hex-encoded salt from the server (from registration)
 * @param serverB     - hex-encoded server public ephemeral B
 */
export async function createSRPProof(
  identity: string,
  password: string,
  serverSalt: string,
  serverB: string,
): Promise<SRPProof> {
  const salt = hexToBytes(serverSalt);
  const B = BigInt('0x' + serverB);

  if (B % N === 0n) throw new Error('SRP: invalid server public value B');

  const k = await getK();
  const x = await computeX(salt, identity, password);

  // Client ephemeral
  let a: bigint;
  let A: bigint;
  do {
    const aBytes = randomBytes(32);
    a = bytesToBigint(aBytes);
    A = modPow(g, a, N);
    aBytes.fill(0);
  } while (A % N === 0n);

  const aBytes = bigintToBytes(A, N_LEN);
  const bBytes = bigintToBytes(B, N_LEN);

  // u = H(pad(A) | pad(B))
  const uHash = await H(aBytes, bBytes);
  const u = bytesToBigint(uHash);
  if (u === 0n) throw new Error('SRP: u is zero, aborting to prevent attack');

  // v = g^x mod N
  const v = modPow(g, x, N);

  // S = (B - k*v)^(a + u*x) mod N
  const kv = (k * v) % N;
  const base = ((B - kv) % N + N) % N;
  const exp = (a + u * x) % (N - 1n);
  const S = modPow(base, exp, N);

  const nBytes = bigintToBytes(N, N_LEN);
  const gBytes = bigintToBytes(g, N_LEN);
  const enc = new TextEncoder();

  // M1 = H(H(N) XOR H(g) | H(I) | salt | A | B | S)
  const hN = await H(nBytes);
  const hg = await H(gBytes);
  const hNxorg = xorBytes(hN, hg);
  const hI = await H(enc.encode(identity));
  const sBytes = bigintToBytes(S, N_LEN);

  const M1 = await H(hNxorg, hI, salt, aBytes, bBytes, sBytes);

  // Zero sensitive values
  sBytes.fill(0);

  return {
    A: bytesToHex(aBytes),
    M1: bytesToHex(M1),
  };
}
