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
