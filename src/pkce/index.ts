/**
 * @module pkce
 *
 * PKCE (Proof Key for Code Exchange) — RFC 7636.
 * Generates code verifiers and SHA-256 code challenges
 * for OAuth 2.0 authorization code flow.
 *
 * @example
 * ```ts
 * import { generateCodeVerifier, generateCodeChallenge } from 'passwordthing/pkce';
 * const verifier = generateCodeVerifier();
 * const challenge = await generateCodeChallenge(verifier);
 * ```
 */

export { generateCodeVerifier, generateCodeChallenge } from './pkce.js';
