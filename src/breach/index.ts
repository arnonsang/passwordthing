/**
 * @module breach
 *
 * Have I Been Pwned (HIBP) k-anonymity password breach checker.
 *
 * @example
 * ```ts
 * import { checkBreach } from 'passwordthing/breach';
 * const result = await checkBreach('password123');
 * // { isPwned: true, occurrences: 3861493 }
 * ```
 */

export type { BreachResult, BreachCheckOptions } from './check.js';
export { checkBreach } from './check.js';
