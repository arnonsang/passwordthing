export { base64URLToArrayBuffer, arrayBufferToBase64URL } from './utils.js';

export type {
  PasskeyRegisterOptions,
  PasskeyRegistrationResponse,
  PasskeyAuthenticateOptions,
  PasskeyAuthenticationResponse,
} from './passkey.js';
export { isSupported, register, authenticate } from './passkey.js';
