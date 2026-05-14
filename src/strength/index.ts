/**
 * @module strength
 *
 * Password strength evaluation using entropy estimation with
 * dictionary checks, keyboard-walk detection, L33t substitution
 * analysis, and configurable scoring presets.
 *
 * @example
 * ```ts
 * import { evaluateStrength } from 'passwordthing/strength';
 * const result = evaluateStrength('MyStr0ng!Pw', { preset: 'OWASP_STRICT' });
 * console.log(result.score, result.label);
 * ```
 */

export type { StrengthPreset, EvaluateStrengthOptions, StrengthResult } from './entropy.js';
export { evaluateStrength } from './entropy.js';
export { BloomFilter, isCommonPassword } from './bloom.js';
