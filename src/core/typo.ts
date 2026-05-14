/**
 * @module core/typo
 *
 * Typo detection using Levenshtein distance.
 *
 * @example
 * ```ts
 * import { checkTypo } from 'passwordthing/core';
 * const result = checkTypo('mypassword', 'mypasword');
 * // { match: false, distance: 1, message: '1 character off' }
 * ```
 */

export interface TypoResult {
  /** Whether the strings are identical. */
  match: boolean;
  /** Levenshtein edit distance. */
  distance: number;
  /** Human-readable comparison result. */
  message: 'Match' | '1 character off' | 'Significantly different';
}

/**
 * Check if two strings differ by a typo (Levenshtein distance).
 *
 * Uses an optimized two-row iterative Levenshtein algorithm with
 * O(n*m) time and O(min(n,m)) space.
 *
 * @param a - First string.
 * @param b - Second string.
 * @returns Typo result with match flag, distance, and message.
 *
 * @example
 * ```ts
 * checkTypo('hello', 'hallo'); // { match: false, distance: 1, message: '1 character off' }
 * checkTypo('hello', 'hello'); // { match: true, distance: 0, message: 'Match' }
 * ```
 */
export function checkTypo(a: string, b: string): TypoResult {
  const distance = levenshtein(a, b);
  const match = distance === 0;
  const message: TypoResult['message'] =
    distance === 0 ? 'Match' : distance === 1 ? '1 character off' : 'Significantly different';
  return { match, distance, message };
}

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const m = a.length;
  const n = b.length;

  let prev: number[] = Array.from({ length: n + 1 }, (_, i) => i);
  let curr: number[] = new Array<number>(n + 1);

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j]! + 1, curr[j - 1]! + 1, prev[j - 1]! + cost);
    }
    const tmp = prev;
    prev = curr;
    curr = tmp;
  }

  return prev[n]!;
}
