/**
 * @module pkce/pkce
 *
 * PKCE code verifier and challenge generation.
 *
 * @example
 * ```ts
 * import { generateCodeVerifier, generateCodeChallenge } from 'passwordthing/pkce';
 * ```
 */

const BASE64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * Generate a PKCE code verifier.
 *
 * Produces a cryptographically random string of the given length
 * using the unreserved base64url character set.
 *
 * @param length - Verifier length, must be 43–128. Default 64.
 * @returns Base64url verifier string.
 * @throws {Error} If length is outside [43, 128].
 */
export function generateCodeVerifier(length = 64): string {
  if (length < 43 || length > 128) {
    throw new Error('Code verifier length must be between 43 and 128');
  }
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => BASE64URL_CHARS[b % 64]!).join('');
}

/**
 * Generate a PKCE code challenge from a verifier (S256 method).
 *
 * Computes `BASE64URL(SHA-256(ASCII(verifier)))` with no padding
 * as specified by RFC 7636.
 *
 * @param verifier - The code verifier string.
 * @returns Base64url-encoded SHA-256 challenge.
 */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
