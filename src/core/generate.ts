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
  length: number;
  includeUppercase?: boolean;
  includeLowercase?: boolean;
  includeDigits?: boolean;
  includeSymbols?: boolean;
  excludeAmbiguous?: boolean;
  pronounceable?: boolean;
  customCharset?: string;
}

// Module-level uint32 entropy buffer — one getRandomValues() per 256 chars amortized
const _rng = new Uint32Array(256);
let _rngIdx = 256;

function nextUint32(): number {
  if (_rngIdx >= _rng.length) {
    globalThis.crypto.getRandomValues(_rng);
    _rngIdx = 0;
  }
  return _rng[_rngIdx++]!;
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

// Reusable output buffer — avoids per-call heap allocation for lengths ≤ 256
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
