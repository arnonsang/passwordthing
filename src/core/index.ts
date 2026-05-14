/**
 * @module core
 *
 * Password generation, validation, and typo detection.
 *
 * @example
 * ```ts
 * import { generate, validate, checkTypo } from 'passwordthing/core';
 * const pw = generate({ length: 16 });
 * const result = validate(pw, { min: 8, digits: 1 });
 * const typo = checkTypo('mypassword', 'mypasword');
 * ```
 */

export type { ValidationOptions, ValidationResult, FailedRule } from './validate.js';
export { validate } from './validate.js';

export type { GeneratorOptions } from './generate.js';
export { generate, generateBatch } from './generate.js';

export type { PassphraseOptions } from './passphrase.js';
export { generatePassphrase } from './passphrase.js';

export type { TypoResult } from './typo.js';
export { checkTypo } from './typo.js';
