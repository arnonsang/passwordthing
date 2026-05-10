const SYMBOL_CHARS = '!@#$%^&*()_+~|}{[]:;?><,./-=';
const SYMBOL_LOOKUP = new Uint8Array(128);
for (let _i = 0; _i < SYMBOL_CHARS.length; _i++) SYMBOL_LOOKUP[SYMBOL_CHARS.charCodeAt(_i)] = 1;

export interface ValidationOptions {
  min?: number;
  max?: number;
  digits?: number;
  lowercase?: number;
  uppercase?: number;
  symbols?: number;
  spaces?: boolean;
  not?: string[];
  is?: (val: string) => boolean | string;
  regex?: RegExp;
  noSequential?: boolean;
  noRepeating?: number;
}

export type FailedRule = { rule: string; message: string };

export type ValidationResult =
  | { isValid: true; failedRules: [] }
  | { isValid: false; failedRules: Array<FailedRule> };

/**
 * Timing-safe comparison of two equal-length strings.
 * Note: length difference leaks length info by design, this guards against
 * character-by-character timing attacks on the character content only.
 */
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

// Reused per call to avoid per-invocation heap allocation (JS is single-threaded)
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

  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);

    if (code >= 48 && code <= 57) _analysis.digits++;
    else if (code >= 97 && code <= 122) _analysis.lower++;
    else if (code >= 65 && code <= 90) _analysis.upper++;
    else if (code < 128 && SYMBOL_LOOKUP[code] === 1) _analysis.symbols++;

    if (!_analysis.hasSpace && (code === 32 || (code >= 9 && code <= 13) || code === 160)) _analysis.hasSpace = true;

    if (!_analysis.isSequential && i >= 2) {
      const prev2 = s.charCodeAt(i - 2);
      const prev1 = s.charCodeAt(i - 1);
      if ((prev1 === prev2 + 1 && code === prev2 + 2) || (prev1 === prev2 - 1 && code === prev2 - 2)) _analysis.isSequential = true;
    }

    if (i > 0) {
      curRepeat = code === s.charCodeAt(i - 1) ? curRepeat + 1 : 1;
      if (curRepeat > _analysis.maxRepeat) _analysis.maxRepeat = curRepeat;
    }
  }

  return _analysis;
}

export function validate(password: string, options: ValidationOptions = {}): ValidationResult {
  const failed: FailedRule[] = [];

  if (options.min !== undefined && password.length < options.min) {
    failed.push({ rule: 'min', message: `Must be at least ${options.min} characters long.` });
  }
  if (options.max !== undefined && password.length > options.max) {
    failed.push({ rule: 'max', message: `Must be no more than ${options.max} characters long.` });
  }

  // Single-pass analysis for all char-level rules
  const needsAnalysis =
    options.digits !== undefined ||
    options.lowercase !== undefined ||
    options.uppercase !== undefined ||
    options.symbols !== undefined ||
    options.spaces === false ||
    options.noSequential === true ||
    options.noRepeating !== undefined;

  if (needsAnalysis) {
    const a = analyzeChars(password);

    if (options.digits !== undefined && a.digits < options.digits) {
      failed.push({ rule: 'digits', message: `Must contain at least ${options.digits} numeric digit(s).` });
    }
    if (options.lowercase !== undefined && a.lower < options.lowercase) {
      failed.push({ rule: 'lowercase', message: `Must contain at least ${options.lowercase} lowercase letter(s).` });
    }
    if (options.uppercase !== undefined && a.upper < options.uppercase) {
      failed.push({ rule: 'uppercase', message: `Must contain at least ${options.uppercase} uppercase letter(s).` });
    }
    if (options.symbols !== undefined && a.symbols < options.symbols) {
      failed.push({ rule: 'symbols', message: `Must contain at least ${options.symbols} symbol(s).` });
    }
    if (options.spaces === false && a.hasSpace) {
      failed.push({ rule: 'spaces', message: 'Must not contain whitespace.' });
    }
    if (options.noSequential === true && a.isSequential) {
      failed.push({ rule: 'noSequential', message: 'Must not contain sequential characters (e.g. "1234", "abcd", "dcba").' });
    }
    if (options.noRepeating !== undefined && a.maxRepeat > options.noRepeating) {
      failed.push({ rule: 'noRepeating', message: `Must not repeat the same character more than ${options.noRepeating} time(s) consecutively.` });
    }
  }

  if (options.not !== undefined) {
    const lower = password.toLowerCase();
    for (const blocked of options.not) {
      if (timingSafeEqual(lower, blocked.toLowerCase())) {
        failed.push({ rule: 'not', message: 'This password is not allowed.' });
        break;
      }
    }
  }
  if (options.regex !== undefined && !options.regex.test(password)) {
    failed.push({ rule: 'regex', message: 'Password does not match the required pattern.' });
  }
  if (options.is !== undefined) {
    const result = options.is(password);
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
