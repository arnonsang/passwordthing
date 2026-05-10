const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*()_+~|}{[]:;?><,./-=';
const AMBIGUOUS = new Set(['i', 'l', '1', 'L', 'o', '0', 'O', 'I']);
const VOWELS = 'aeiouy';
const CONSONANTS = 'bcdfghjklmnpqrstvwxz';

// Pre-computed ambiguous-filtered pools (computed once at module load)
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

// Module-level entropy buffer: one getRandomValues() call per 256 characters instead of one per character.
const _rng = new Uint32Array(256);
let _rngIdx = 256; // start exhausted so first call triggers a fill

function nextUint32(): number {
  if (_rngIdx >= _rng.length) {
    globalThis.crypto.getRandomValues(_rng);
    _rngIdx = 0;
  }
  return _rng[_rngIdx++]!;
}

/**
 * Unbiased random integer in [0, max) using rejection sampling.
 */
function randomInt(max: number): number {
  const threshold = (2 ** 32) % max;
  let v: number;
  do {
    v = nextUint32();
  } while (v < threshold);
  return v % max;
}

// Charset cache: index = flagBits (upper=8, lower=4, digits=2, symbols=1) | (excludeAmbiguous ? 16 : 0)
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
  const charset = lookupCharset(flagBits, excludeAmbiguous);
  if (charset.length === 0) throw new Error('No character pool selected; enable at least one character set.');

  return generateFromCharset(charset, length);
}

function generateFromCharset(charset: string, length: number): string {
  const csLen = charset.length;
  const threshold = (2 ** 32) % csLen;
  const buf = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    let v: number;
    do { v = nextUint32(); } while (v < threshold);
    buf[i] = charset.charCodeAt(v % csLen);
  }
  return String.fromCharCode(...buf);
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

  const buf = new Uint8Array(length);
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

  return String.fromCharCode(...buf);
}
