/**
 * @module core/generate
 *
 * Cryptographically secure password generator with amortized CSPRNG
 * buffering and pre-computed charset byte caches for zero-allocation hot paths.
 *
 * @example
 * ```ts
 * import { generate } from 'passwordthing/core';
 * const pw = generate({ length: 16, includeSymbols: true });
 * ```
 */

import { nextUint32 } from './_rng.js';

const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*()_+~|}{[]:;?><,./-=';
const AMBIGUOUS = new Set(['i', 'l', '1', 'L', 'o', '0', 'O', 'I']);
const VOWELS = 'aeiouy';
const CONSONANTS = 'bcdfghjklmnpqrstvwxz';

const UPPERCASE_CLEAN = UPPERCASE.split('').filter((c) => !AMBIGUOUS.has(c)).join('');
const LOWERCASE_CLEAN = LOWERCASE.split('').filter((c) => !AMBIGUOUS.has(c)).join('');
const DIGITS_CLEAN = DIGITS.split('').filter((c) => !AMBIGUOUS.has(c)).join('');
const VOWELS_CLEAN = VOWELS.split('').filter((c) => !AMBIGUOUS.has(c)).join('');
const CONSONANTS_CLEAN = CONSONANTS.split('').filter((c) => !AMBIGUOUS.has(c)).join('');

export interface GeneratorOptions {
  /** Password length (must be >= 1). */
  length: number;
  /** Include uppercase letters. Default `true`. */
  includeUppercase?: boolean;
  /** Include lowercase letters. Default `true`. */
  includeLowercase?: boolean;
  /** Include numeric digits. Default `true`. */
  includeDigits?: boolean;
  /** Include symbols. Default `false`. */
  includeSymbols?: boolean;
  /** Exclude ambiguous characters (i, l, 1, L, o, 0, O, I). */
  excludeAmbiguous?: boolean;
  /** Generate pronounceable password (vowel-consonant alternation). */
  pronounceable?: boolean;
  /** Custom character set to use instead of built-in pools. */
  customCharset?: string;
}

// Charset string cache: index = flagBits | (excludeAmbiguous ? 16 : 0)
const CHARSET_CACHE = new Array<string | undefined>(32).fill(undefined);

function lookupCharset(flagBits: number, excludeAmbiguous: boolean): string {
  const idx = flagBits | (excludeAmbiguous ? 16 : 0);
  let cs = CHARSET_CACHE[idx];
  if (cs !== undefined) return cs;
  cs = '';
  if (flagBits & 8) cs += excludeAmbiguous ? UPPERCASE_CLEAN : UPPERCASE;
  if (flagBits & 4) cs += excludeAmbiguous ? LOWERCASE_CLEAN : LOWERCASE;
  if (flagBits & 2) cs += excludeAmbiguous ? DIGITS_CLEAN : DIGITS;
  if (flagBits & 1) cs += SYMBOLS;
  CHARSET_CACHE[idx] = cs;
  return cs;
}

// Pre-computed Uint8Array of char codes per charset — avoids charCodeAt() per character generated
const CHARSET_BYTES_CACHE = new Array<Uint8Array | undefined>(32).fill(undefined);

function lookupCharsetBytes(flagBits: number, excludeAmbiguous: boolean): Uint8Array {
  const idx = flagBits | (excludeAmbiguous ? 16 : 0);
  let cb = CHARSET_BYTES_CACHE[idx];
  if (cb !== undefined) return cb;
  const cs = lookupCharset(flagBits, excludeAmbiguous);
  cb = new Uint8Array(cs.length);
  for (let i = 0; i < cs.length; i++) cb[i] = cs.charCodeAt(i);
  CHARSET_BYTES_CACHE[idx] = cb;
  return cb;
}

// Reusable output buffer for lengths <= 256
const _outBuf = new Uint8Array(256);
// TextDecoder for zero-copy Uint8Array → string (latin1 covers all ASCII + extended)
const _decoder = new TextDecoder('latin1');

function strFromBytes(buf: Uint8Array, len: number): string {
  return _decoder.decode(len <= _outBuf.length ? buf.subarray(0, len) : buf);
}

function generateFromCharsetBytes(charsetBytes: Uint8Array, length: number): string {
  const csLen = charsetBytes.length;
  const threshold = (2 ** 32) % csLen;
  const buf = length <= _outBuf.length ? _outBuf : new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    let v: number;
    do { v = nextUint32(); } while (v < threshold);
    buf[i] = charsetBytes[v % csLen];
  }
  return strFromBytes(buf, length);
}

// Fallback path for customCharset (not cached)
function generateFromCharset(charset: string, length: number): string {
  const cb = new Uint8Array(charset.length);
  for (let i = 0; i < charset.length; i++) cb[i] = charset.charCodeAt(i);
  return generateFromCharsetBytes(cb, length);
}

/**
 * Generate a cryptographically secure random password.
 *
 * Uses an internal entropy buffer (256 `uint32` values) to amortize
 * `crypto.getRandomValues()` calls across many characters. Rejection
 * sampling avoids modular bias.
 *
 * @param options - Generator options.
 * @returns Generated password string.
 *
 * @throws {RangeError} If `length < 1`.
 * @throws {Error} If no character pool can be built from the flags.
 *
 * @example
 * ```ts
 * // Standard password
 * generate({ length: 16 });
 *
 * // With symbols and no ambiguous chars
 * generate({ length: 20, includeSymbols: true, excludeAmbiguous: true });
 *
 * // Pronounceable
 * generate({ length: 12, pronounceable: true });
 *
 * // Custom charset
 * generate({ length: 8, customCharset: 'abc123' });
 * ```
 */
export function generate(options: GeneratorOptions): string {
  const {
    length,
    customCharset,
    pronounceable = false,
    includeUppercase = true,
    includeLowercase = true,
    includeDigits = true,
    includeSymbols = false,
    excludeAmbiguous = false,
  } = options;

  if (length < 1) throw new RangeError('length must be at least 1');

  if (customCharset !== undefined) {
    if (customCharset.length === 0) throw new Error('customCharset must not be empty');
    return generateFromCharset(customCharset, length);
  }

  if (pronounceable) {
    return generatePronounceable(length, includeDigits, includeSymbols, excludeAmbiguous);
  }

  const flagBits = (includeUppercase ? 8 : 0) | (includeLowercase ? 4 : 0) | (includeDigits ? 2 : 0) | (includeSymbols ? 1 : 0);
  const charsetBytes = lookupCharsetBytes(flagBits, excludeAmbiguous);
  if (charsetBytes.length === 0) throw new Error('No character pool selected; enable at least one character set.');

  return generateFromCharsetBytes(charsetBytes, length);
}

function generatePronounceable(
  length: number,
  appendDigits: boolean,
  appendSymbols: boolean,
  excludeAmbiguous: boolean,
): string {
  const extras = (appendDigits ? 1 : 0) + (appendSymbols ? 1 : 0);
  const alphaLen = Math.max(1, length - extras);

  const vowelPool = excludeAmbiguous ? VOWELS_CLEAN : VOWELS;
  const consonantPool = excludeAmbiguous ? CONSONANTS_CLEAN : CONSONANTS;

  const buf = length <= _outBuf.length ? _outBuf : new Uint8Array(length);
  let pos = 0;
  let useVowel = (nextUint32() & 1) === 0;
  for (let i = 0; i < alphaLen; i++) {
    const pool = useVowel ? vowelPool : consonantPool;
    const thr = (2 ** 32) % pool.length;
    let v: number;
    do { v = nextUint32(); } while (v < thr);
    buf[pos++] = pool.charCodeAt(v % pool.length);
    useVowel = !useVowel;
  }

  if (appendDigits) {
    const digitPool = excludeAmbiguous ? '23456789' : DIGITS;
    const thr = (2 ** 32) % digitPool.length;
    let v: number;
    do { v = nextUint32(); } while (v < thr);
    buf[pos++] = digitPool.charCodeAt(v % digitPool.length);
  }
  if (appendSymbols) {
    const thr = (2 ** 32) % SYMBOLS.length;
    let v: number;
    do { v = nextUint32(); } while (v < thr);
    buf[pos++] = SYMBOLS.charCodeAt(v % SYMBOLS.length);
  }

  return strFromBytes(buf, length);
}

/**
 * Generate multiple cryptographically secure random passwords in one call.
 *
 * @param count - Number of passwords to generate (must be >= 1).
 * @param options - Generator options applied to every password.
 * @returns Array of generated password strings.
 *
 * @throws {RangeError} If `count < 1`.
 *
 * @example
 * ```ts
 * const suggestions = generateBatch(5, { length: 16, includeSymbols: true });
 * ```
 */
export function generateBatch(count: number, options: GeneratorOptions): string[] {
  if (count < 1) throw new RangeError('count must be at least 1');
  return Array.from({ length: count }, () => generate(options));
}
