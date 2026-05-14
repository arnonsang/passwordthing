/**
 * @module passkey/utils
 *
 * Low-level Base64URL ↔ ArrayBuffer utilities for WebAuthn.
 * All WebAuthn binary fields use base64url encoding (no padding).
 */

/**
 * Decode a base64url string to an ArrayBuffer.
 *
 * @param base64url - Base64url-encoded string.
 * @returns Decoded ArrayBuffer.
 */
export function base64URLToArrayBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/**
 * Encode an ArrayBuffer to a base64url string (no padding).
 *
 * @param buffer - ArrayBuffer to encode.
 * @returns Base64url-encoded string.
 */
export function arrayBufferToBase64URL(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
