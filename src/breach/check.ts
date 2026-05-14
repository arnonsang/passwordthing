/**
 * @module breach/check
 *
 * Checks passwords against Have I Been Pwned (HIBP) using
 * k-anonymity: only the first 5 characters of the SHA-1 hash
 * are sent over the network. Includes padding header to
 * mitigate traffic-analysis attacks.
 *
 * @example
 * ```ts
 * import { checkBreach } from 'passwordthing/breach';
 * const { isPwned, occurrences } = await checkBreach('hunter2');
 * ```
 */

export interface BreachResult {
  /** Whether the password appeared in known data breaches. */
  isPwned: boolean;
  /** How many times the password appeared across breaches. */
  occurrences: number;
}

export interface BreachCheckOptions {
  /** AbortSignal to cancel the request. */
  signal?: AbortSignal;
  /** Request timeout in milliseconds. Default `5000`. Set to `0` to disable. */
  timeoutMs?: number;
  /**
   * Cache HIBP prefix responses to avoid redundant fetches for passwords sharing
   * the same first 5 SHA-1 hash characters.
   *
   * `'session'` stores responses in `sessionStorage` (browser only, SSR-safe).
   * `'none'` (default) disables caching.
   */
  cache?: 'session' | 'none';
}

const HIBP_URL = 'https://api.pwnedpasswords.com/range/';

async function sha1Hex(input: string): Promise<string> {
  const encoded = new TextEncoder().encode(input);
  const buffer = await globalThis.crypto.subtle.digest('SHA-1', encoded);
  const bytes = new Uint8Array(buffer);
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

function parseHibpResponse(body: string, suffix: string): number {
  const lines = body.split('\n');
  for (const line of lines) {
    const sep = line.indexOf(':');
    if (sep === -1) continue;
    const lineSuffix = line.slice(0, sep).trim().toUpperCase();
    if (lineSuffix === suffix) {
      return parseInt(line.slice(sep + 1).trim(), 10);
    }
  }
  return 0;
}

function sessionGet(key: string): string | null {
  try {
    return (globalThis as unknown as { sessionStorage?: Storage }).sessionStorage?.getItem(key) ?? null;
  } catch {
    return null;
  }
}

function sessionSet(key: string, value: string): void {
  try {
    (globalThis as unknown as { sessionStorage?: Storage }).sessionStorage?.setItem(key, value);
  } catch {
    // unavailable in SSR or private-browsing quota exhaustion
  }
}

/**
 * Check whether a password has been exposed in known data breaches.
 *
 * Uses the HIBP k-anonymity model: the SHA-1 hash of the password
 * is computed locally, then only the first 5 hex characters are
 * sent to the API. The response (a list of matching hash suffixes)
 * is checked locally.
 *
 * Includes the `Add-Padding: true` header for traffic-analysis
 * resistance.
 *
 * @param password - The password to check.
 * @param options - Optional timeout, abort signal, and response caching.
 * @returns Breach result with `isPwned` flag and occurrence count.
 *
 * @throws {Error} If the HIBP API returns a non-2xx status.
 * @throws {DOMException} If the request times out or is aborted.
 *
 * @example
 * ```ts
 * const result = await checkBreach('password123');
 * if (result.isPwned) {
 *   console.log(`Found ${result.occurrences} times in breaches`);
 * }
 *
 * // With timeout and session caching
 * const result2 = await checkBreach('mypassword', { timeoutMs: 3000, cache: 'session' });
 * ```
 */
export async function checkBreach(
  password: string,
  options: BreachCheckOptions = {},
): Promise<BreachResult> {
  const { signal, timeoutMs = 5000, cache = 'none' } = options;

  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const cacheKey = `pt_hibp_${prefix}`;
  let body: string | null = cache === 'session' ? sessionGet(cacheKey) : null;

  if (body === null) {
    let fetchSignal: AbortSignal | undefined = signal;
    let timeoutId: ReturnType<typeof setTimeout> | undefined;

    if (timeoutMs > 0) {
      const timeoutCtrl = new AbortController();
      timeoutId = setTimeout(
        () => timeoutCtrl.abort(new DOMException('Request timed out', 'TimeoutError')),
        timeoutMs,
      );

      if (signal !== undefined) {
        const combined = new AbortController();
        signal.addEventListener('abort', () => combined.abort(signal.reason), { once: true });
        timeoutCtrl.signal.addEventListener('abort', () => combined.abort(timeoutCtrl.signal.reason), { once: true });
        fetchSignal = combined.signal;
      } else {
        fetchSignal = timeoutCtrl.signal;
      }
    }

    try {
      const response = await fetch(`${HIBP_URL}${prefix}`, {
        headers: { 'Add-Padding': 'true' },
        ...(fetchSignal !== undefined ? { signal: fetchSignal } : {}),
      });

      if (!response.ok) {
        throw new Error(`HIBP API error: ${response.status} ${response.statusText}`);
      }

      body = await response.text();
    } finally {
      if (timeoutId !== undefined) clearTimeout(timeoutId);
    }

    if (cache === 'session') sessionSet(cacheKey, body);
  }

  const occurrences = parseHibpResponse(body, suffix);
  return { isPwned: occurrences > 0, occurrences };
}
