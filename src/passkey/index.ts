/**
 * @module passkey
 *
 * WebAuthn/Passkey utilities with dual API surface:
 * flat field-by-field options and server-format options
 * (base64url strings matching server-side WebAuthn).
 *
 * @example
 * ```ts
 * import { register, authenticate } from 'passwordthing/passkey';
 *
 * const credential = await register({
 *   challenge: '...',
 *   rpId: 'example.com',
 *   rpName: 'Example',
 *   userId: '...',
 *   userName: 'alice',
 *   userDisplayName: 'Alice',
 * });
 * ```
 */

export { base64URLToArrayBuffer, arrayBufferToBase64URL } from './utils.js';

export type {
  PasskeyRegisterOptions,
  PasskeyRegistrationResponse,
  PasskeyAuthenticateOptions,
  PasskeyAuthenticationResponse,
  ServerRegistrationOptions,
  ServerAuthenticationOptions,
  ServerCredentialDescriptor,
} from './passkey.js';
export { isSupported, register, authenticate, registerWithServerOptions, authenticateWithServerOptions } from './passkey.js';
