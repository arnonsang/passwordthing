/**
 * @module core/validate
 *
 * Password validation engine with single-pass character analysis,
 * constant-time blocklist matching, and support for custom validators.
 *
 * @example
 * ```ts
 * import { validate } from 'passwordthing/core';
 * const result = validate('MyStr0ng!Pw', {
 *   min: 8,
 *   digits: 1,
 *   uppercase: 1,
 *   symbols: 1,
 *   noSequential: true,
 * });
 * ```
 */

const SYMBOL_CHARS = '!@#$%^&*()_+~|}{[]:;?><,./-=';
const SYMBOL_LOOKUP = new Uint8Array(128);
for (let _i = 0; _i < SYMBOL_CHARS.length; _i++) SYMBOL_LOOKUP[SYMBOL_CHARS.charCodeAt(_i)] = 1;

export interface ValidationOptions {
  /** Minimum length. */
  min?: number;
  /** Maximum length. */
  max?: number;
  /** Minimum number of digits. */
  digits?: number;
  /** Minimum number of lowercase letters. */
  lowercase?: number;
  /** Minimum number of uppercase letters. */
  uppercase?: number;
  /** Minimum number of symbol characters. */
  symbols?: number;
  /** If `false`, whitespace is not allowed. */
  spaces?: boolean;
  /** Blocked passwords (case-insensitive constant-time comparison). */
  not?: string[];
  /** Custom validator returning `true` for pass, or a `string` message for fail. */
  is?: (val: string) => boolean | string;
  /** Regex pattern the password must match. */
  regex?: RegExp;
  /** If `true`, disallow sequential characters (e.g. "1234", "abcd"). */
  noSequential?: boolean;
  /** Maximum consecutive repeats of the same character. */
  noRepeating?: number;
}

export type FailedRule = { rule: string; message: string };

export type ValidationResult =
  | { isValid: true; failedRules: [] }
  | { isValid: false; failedRules: Array<FailedRule> };

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let acc = 0;
  for (let i = 0; i < a.length; i++) {
    acc |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return acc === 0;
}

interface CharAnalysis {
  digits: number;
  lower: number;
  upper: number;
  symbols: number;
  hasSpace: boolean;
  isSequential: boolean;
  maxRepeat: number;
}

const _analysis: CharAnalysis = { digits: 0, lower: 0, upper: 0, symbols: 0, hasSpace: false, isSequential: false, maxRepeat: 0 };

function analyzeChars(s: string): CharAnalysis {
  _analysis.digits = 0;
  _analysis.lower = 0;
  _analysis.upper = 0;
  _analysis.symbols = 0;
  _analysis.hasSpace = false;
  _analysis.isSequential = false;
  _analysis.maxRepeat = s.length > 0 ? 1 : 0;
  let curRepeat = 1;
  let prevCode = 0;
  let prevPrevCode = 0;

  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);

    if (code >= 48 && code <= 57) _analysis.digits++;
    else if (code >= 97 && code <= 122) _analysis.lower++;
    else if (code >= 65 && code <= 90) _analysis.upper++;
    else if (code < 128 && SYMBOL_LOOKUP[code] === 1) _analysis.symbols++;

    if (!_analysis.hasSpace && (code === 32 || (code >= 9 && code <= 13) || code === 160)) _analysis.hasSpace = true;

    if (!_analysis.isSequential && i >= 2) {
      const d1 = code - prevCode;
      const d2 = prevCode - prevPrevCode;
      if ((d1 === 1 && d2 === 1) || (d1 === -1 && d2 === -1)) _analysis.isSequential = true;
    }

    if (i > 0) {
      curRepeat = code === prevCode ? curRepeat + 1 : 1;
      if (curRepeat > _analysis.maxRepeat) _analysis.maxRepeat = curRepeat;
    }

    prevPrevCode = prevCode;
    prevCode = code;
  }

  return _analysis;
}

/**
 * Validate a password against the given options.
 *
 * Performs a single-pass character analysis and applies each
 * requested rule. Blocklisted passwords are compared with
 * constant-time comparison to prevent timing side-channels.
 *
 * @param password - The password to validate.
 * @param options - Validation rules.
 * @returns Validation result (isValid + optional failed rules).
 *
 * @example
 * ```ts
 * const result = validate('abc', { min: 8, digits: 1 });
 * if (!result.isValid) {
 *   for (const { rule, message } of result.failedRules) {
 *     console.error(`${rule}: ${message}`);
 *   }
 * }
 * ```
 */
export function validate(password: string, options: ValidationOptions = {}): ValidationResult {
  const failed: FailedRule[] = [];

  const { min, max, digits, lowercase, uppercase, symbols, spaces, not, is: customIs, regex, noSequential, noRepeating } = options;

  if (min !== undefined && password.length < min) {
    failed.push({ rule: 'min', message: `Must be at least ${min} characters long.` });
  }
  if (max !== undefined && password.length > max) {
    failed.push({ rule: 'max', message: `Must be no more than ${max} characters long.` });
  }

  const needsAnalysis =
    digits !== undefined ||
    lowercase !== undefined ||
    uppercase !== undefined ||
    symbols !== undefined ||
    spaces === false ||
    noSequential === true ||
    noRepeating !== undefined;

  if (needsAnalysis) {
    const a = analyzeChars(password);

    if (digits !== undefined && a.digits < digits) {
      failed.push({ rule: 'digits', message: `Must contain at least ${digits} numeric digit(s).` });
    }
    if (lowercase !== undefined && a.lower < lowercase) {
      failed.push({ rule: 'lowercase', message: `Must contain at least ${lowercase} lowercase letter(s).` });
    }
    if (uppercase !== undefined && a.upper < uppercase) {
      failed.push({ rule: 'uppercase', message: `Must contain at least ${uppercase} uppercase letter(s).` });
    }
    if (symbols !== undefined && a.symbols < symbols) {
      failed.push({ rule: 'symbols', message: `Must contain at least ${symbols} symbol(s).` });
    }
    if (spaces === false && a.hasSpace) {
      failed.push({ rule: 'spaces', message: 'Must not contain whitespace.' });
    }
    if (noSequential === true && a.isSequential) {
      failed.push({ rule: 'noSequential', message: 'Must not contain sequential characters (e.g. "1234", "abcd", "dcba").' });
    }
    if (noRepeating !== undefined && a.maxRepeat > noRepeating) {
      failed.push({ rule: 'noRepeating', message: `Must not repeat the same character more than ${noRepeating} time(s) consecutively.` });
    }
  }

  if (not !== undefined) {
    const lower = password.toLowerCase();
    for (const blocked of not) {
      if (timingSafeEqual(lower, blocked.toLowerCase())) {
        failed.push({ rule: 'not', message: 'This password is not allowed.' });
        break;
      }
    }
  }
  if (regex !== undefined && !regex.test(password)) {
    failed.push({ rule: 'regex', message: 'Password does not match the required pattern.' });
  }
  if (customIs !== undefined) {
    const result = customIs(password);
    if (result !== true) {
      failed.push({
        rule: 'is',
        message: typeof result === 'string' ? result : 'Password failed custom validation.',
      });
    }
  }

  if (failed.length === 0) return { isValid: true, failedRules: [] };
  return { isValid: false, failedRules: failed };
}
