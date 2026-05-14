/**
 * @module strength/entropy
 *
 * Entropy-based password strength evaluator with keyboard walk
 * detection (horizontal rows + vertical columns), date pattern
 * analysis, L33t substitution analysis, common-password lookup,
 * repetition penalty, and user-input penalty. Produces a 0-4 score
 * with crack-time estimates and actionable feedback.
 *
 * @example
 * ```ts
 * import { evaluateStrength } from 'passwordthing/strength';
 * const r = evaluateStrength('p4ssw0rd');
 * // { score: 0, label: 'Very Weak', ... }
 * ```
 */

import { isCommonPassword } from './bloom.js';
import { type StrengthPreset, PRESET_THRESHOLDS } from './presets.js';

export type { StrengthPreset };

export interface EvaluateStrengthOptions {
  /** Scoring preset. Default `'BASIC'`. */
  preset?: StrengthPreset;
  /** Known user data (name, email, etc.) checked for substring inclusion. */
  userInputs?: string[];
}

export interface StrengthResult {
  /** Overall strength score from 0 (weakest) to 4 (strongest). */
  score: 0 | 1 | 2 | 3 | 4;
  /** Estimated entropy in bits. */
  entropyBits: number;
  /** Human-readable strength label. */
  label: 'Very Weak' | 'Weak' | 'Fair' | 'Strong' | 'Very Strong';
  /** Estimated crack times under two adversarial models. */
  timeToCrack: {
    /** ~10 billion guesses/second (GPU cluster, fast hash like MD5). */
    offlineFastHashing: string;
    /** ~10 guesses/second (online service with rate limiting). */
    onlineThrottled: string;
  };
  /** Actionable feedback for the user. */
  feedback: {
    /** Primary warning, or null if none. */
    warning: string | null;
    /** Specific suggestions to improve the password. */
    suggestions: string[];
  };
}


const L33T: Record<string, string> = {
  '@': 'a', '4': 'a', '8': 'b', '3': 'e', '6': 'g',
  '1': 'i', '!': 'i', '0': 'o', '9': 'g', '5': 's',
  '$': 's', '7': 't', '+': 't', '%': 'x', '2': 'z',
};

function deL33t(s: string): string {
  return s.toLowerCase().replace(/[@48361!0$957+%2]/g, (c) => L33T[c] ?? c);
}


const KB_ROWS = [
  'qwertyuiop',
  'asdfghjkl',
  'zxcvbnm',
  '1234567890',
];
const KB_ROWS_REV = KB_ROWS.map((r) => r.split('').reverse().join(''));

const KB_NGRAMS = new Set<string>();

// Horizontal row n-grams (length >= 4)
for (let _ri = 0; _ri < KB_ROWS.length; _ri++) {
  const _row = KB_ROWS[_ri]!;
  const _rev = KB_ROWS_REV[_ri]!;
  const _rl = _row.length;
  for (let _len = 4; _len <= _rl; _len++) {
    for (let _st = 0; _st <= _rl - _len; _st++) {
      KB_NGRAMS.add(_row.slice(_st, _st + _len));
      KB_NGRAMS.add(_rev.slice(_rl - _st - _len, _rl - _st));
    }
  }
}

// Vertical column sequences (forward and reversed, exact 3-key columns)
const KB_COLS = ['qaz', 'wsx', 'edc', 'rfv', 'tgb', 'yhn', 'ujm'];
for (const _col of KB_COLS) {
  KB_NGRAMS.add(_col);
  KB_NGRAMS.add(_col.split('').reverse().join(''));
}

function hasKeyboardWalk(s: string, minLen = 3): boolean {
  const lower = s.toLowerCase();
  const maxWindow = Math.min(lower.length, 10);
  for (let len = minLen; len <= maxWindow; len++) {
    for (let start = 0; start <= lower.length - len; start++) {
      if (KB_NGRAMS.has(lower.slice(start, start + len))) return true;
    }
  }
  return false;
}


// Date patterns: standalone years, 8-digit dates, separator-style dates
const DATE_YEAR = /(19|20)\d{2}/;
const DATE_8 = /(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])|(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(19|20)\d{2}/;
const DATE_SEP = /(0?[1-9]|1[0-2])[/\-.](0?[1-9]|[12]\d|3[01])[/\-.]((19|20)?\d{2})/;

function hasDatePattern(s: string): boolean {
  return DATE_8.test(s) || DATE_SEP.test(s) || DATE_YEAR.test(s);
}


function charPoolSize(s: string): number {
  let hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false, hasUnicode = false;
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code >= 97 && code <= 122) hasLower = true;
    else if (code >= 65 && code <= 90) hasUpper = true;
    else if (code >= 48 && code <= 57) hasDigit = true;
    else if (code < 128) hasSymbol = true;
    else hasUnicode = true;
    if (hasLower && hasUpper && hasDigit && hasSymbol && hasUnicode) break;
  }
  return Math.max(
    (hasLower ? 26 : 0) + (hasUpper ? 26 : 0) + (hasDigit ? 10 : 0) +
    (hasSymbol ? 32 : 0) + (hasUnicode ? 128 : 0),
    1,
  );
}


function formatSeconds(sec: number): string {
  if (sec < 1) return 'less than a second';
  if (sec < 60) return `${Math.round(sec)} second${sec < 2 ? '' : 's'}`;
  const m = sec / 60;
  if (m < 60) return `${Math.round(m)} minute${Math.round(m) < 2 ? '' : 's'}`;
  const h = m / 60;
  if (h < 24) return `${Math.round(h)} hour${Math.round(h) < 2 ? '' : 's'}`;
  const d = h / 24;
  if (d < 365) return `${Math.round(d)} day${Math.round(d) < 2 ? '' : 's'}`;
  const y = d / 365;
  if (y < 1e6) return `${Math.round(y).toLocaleString('en-US')} year${Math.round(y) < 2 ? '' : 's'}`;
  if (y < 1e9) return `${(y / 1e6).toFixed(1)} million years`;
  if (y < 1e12) return `${(y / 1e9).toFixed(1)} billion years`;
  return 'centuries';
}


const SCORE_LABELS: StrengthResult['label'][] = [
  'Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong',
];

function entropyToScore(
  bits: number,
  thresholds: readonly [number, number, number, number],
): 0 | 1 | 2 | 3 | 4 {
  if (bits < thresholds[0]) return 0;
  if (bits < thresholds[1]) return 1;
  if (bits < thresholds[2]) return 2;
  if (bits < thresholds[3]) return 3;
  return 4;
}


const OFFLINE_FAST_GPS = 1e10;
const ONLINE_THROTTLED_GPS = 10;

/**
 * Evaluate the strength of a password.
 *
 * Computes base entropy as `L x log2(R)` where L is length and R
 * is the guessed character-pool size. Applies penalties for:
 *
 * - Dictionary hits (caps at 15 bits for exact match, 50% cut for L33t).
 * - Keyboard walks: horizontal rows (>= 4 chars) and vertical columns (>= 3 chars), 40% cut.
 * - Date patterns (year, YYYYMMDD, MM/DD/YYYY, etc.), 30% cut.
 * - High character repetition (dominant char > 40% of password), proportional cut.
 * - User-input substrings, 60% cut.
 *
 * @param password - The password to evaluate.
 * @param options - Optional preset and user inputs.
 * @returns Strength result with score, entropy, and feedback.
 *
 * @example
 * ```ts
 * evaluateStrength('CorrectHorseBatteryStaple');
 * // score: 4, label: 'Very Strong'
 * ```
 */
export function evaluateStrength(
  password: string,
  options: EvaluateStrengthOptions = {},
): StrengthResult {
  const preset = options.preset ?? 'BASIC';
  const thresholds = PRESET_THRESHOLDS[preset];

  if (password.length === 0) {
    return {
      score: 0,
      entropyBits: 0,
      label: 'Very Weak',
      timeToCrack: { offlineFastHashing: 'less than a second', onlineThrottled: 'less than a second' },
      feedback: { warning: 'Password is empty.', suggestions: ['Enter a password.'] },
    };
  }

  const R = charPoolSize(password);
  let entropyBits = password.length * Math.log2(R);

  const warnings: string[] = [];
  const suggestions: string[] = [];

  // Dictionary check
  if (isCommonPassword(password)) {
    entropyBits = Math.min(entropyBits, 15);
    warnings.push('This is a very common password.');
    suggestions.push('Add a few uncommon words or characters.');
  } else if (isCommonPassword(deL33t(password))) {
    entropyBits *= 0.5;
    warnings.push('This looks like a common password with character substitutions.');
    suggestions.push('Avoid predictable substitutions like @ for a or 3 for e.');
  }

  // Keyboard walk penalty (rows >= 4 chars, columns >= 3 chars)
  if (hasKeyboardWalk(password)) {
    entropyBits *= 0.6;
    warnings.push('This contains a keyboard pattern.');
    suggestions.push('Avoid sequences like "qwerty", "asdfgh", or "qaz".');
  }

  // Date pattern penalty
  if (hasDatePattern(password)) {
    entropyBits *= 0.7;
    if (warnings.length === 0) warnings.push('This contains a date or year pattern.');
    suggestions.push('Avoid using dates or years in your password.');
  }

  // Repetition penalty: dominant character takes up > 40% of password
  if (password.length >= 4) {
    const freq = new Map<string, number>();
    for (const c of password) freq.set(c, (freq.get(c) ?? 0) + 1);
    let maxFreq = 0;
    for (const v of freq.values()) if (v > maxFreq) maxFreq = v;
    const dominance = maxFreq / password.length;
    if (dominance > 0.4) {
      entropyBits *= Math.max(0.3, 1 - dominance);
      suggestions.push('Avoid repeating the same character many times.');
    }
  }

  // User inputs penalty
  if (options.userInputs !== undefined) {
    const lower = password.toLowerCase();
    for (const input of options.userInputs) {
      if (input.length > 2 && lower.includes(input.toLowerCase())) {
        entropyBits *= 0.4;
        warnings.push('Your password contains personal information.');
        suggestions.push('Avoid using your name, email, or other personal details.');
        break;
      }
    }
  }

  // Length suggestions
  if (password.length < 8) {
    suggestions.push('Use at least 8 characters.');
  } else if (password.length < 12) {
    suggestions.push('Consider using 12 or more characters for better security.');
  }
  if (!/[A-Z]/.test(password)) suggestions.push('Add uppercase letters.');
  if (!/[a-z]/.test(password)) suggestions.push('Add lowercase letters.');
  if (!/[0-9]/.test(password)) suggestions.push('Add numbers.');
  if (!/[^a-zA-Z0-9]/.test(password)) suggestions.push('Add special characters (e.g. ! @ # $).');

  entropyBits = Math.max(0, entropyBits);

  const score = entropyToScore(entropyBits, thresholds);
  const label = SCORE_LABELS[score];

  const guesses = Math.pow(2, entropyBits);
  const offlineSec = guesses / OFFLINE_FAST_GPS;
  const onlineSec = guesses / ONLINE_THROTTLED_GPS;

  return {
    score,
    entropyBits: parseFloat(entropyBits.toFixed(2)),
    label,
    timeToCrack: {
      offlineFastHashing: formatSeconds(offlineSec),
      onlineThrottled: formatSeconds(onlineSec),
    },
    feedback: {
      warning: warnings[0] ?? null,
      suggestions: [...new Set(suggestions)],
    },
  };
}
