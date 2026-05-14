/**
 * @module passkey/passkey
 *
 * WebAuthn passkey registration and authentication with dual
 * API surface.
 *
 * **Flat API** — field-by-field options for simple integration:
 * `register()`, `authenticate()`.
 *
 * **Server-options API** — accepts options in the format sent
 * by any WebAuthn server (base64url strings):
 * `registerWithServerOptions()`, `authenticateWithServerOptions()`.
 *
 * @example
 * ```ts
 * import { registerWithServerOptions } from 'passwordthing/passkey';
 * const cred = await registerWithServerOptions(serverOptions);
 * ```
 */

import { base64URLToArrayBuffer, arrayBufferToBase64URL } from './utils.js';


//Server-options types (base64url strings, as sent by any WebAuthn server)
/** Credential descriptor in server format (base64url id). */
export interface ServerCredentialDescriptor {
  /** Base64url-encoded credential ID. */
  id: string;
  type: 'public-key';
  transports?: AuthenticatorTransport[];
}

/** Registration options in server format (base64url strings). */
export interface ServerRegistrationOptions {
  /** Base64url-encoded challenge. */
  challenge: string;
  /** Relying party info. */
  rp: { id?: string; name: string };
  /** User info with base64url-encoded ID. */
  user: { id: string; name: string; displayName: string };
  /** Public key credential parameters. */
  pubKeyCredParams: Array<{ type: 'public-key'; alg: number }>;
  /** Timeout in ms. Default 60000. */
  timeout?: number;
  /** Attestation conveyance. Default `'none'`. */
  attestation?: AttestationConveyancePreference;
  /** Authenticator selection criteria. */
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  /** Credentials to exclude from registration. */
  excludeCredentials?: ServerCredentialDescriptor[];
}

/** Authentication options in server format (base64url strings). */
export interface ServerAuthenticationOptions {
  /** Base64url-encoded challenge. */
  challenge: string;
  /** Relying party ID (optional, inferred from origin if omitted). */
  rpId?: string;
  /** Timeout in ms. Default 60000. */
  timeout?: number;
  /** User verification requirement. Default `'preferred'`. */
  userVerification?: UserVerificationRequirement;
  /** Allowed credentials for authentication. */
  allowCredentials?: ServerCredentialDescriptor[];
}

// Flat options types (manual field-by-field API)
/** Registration options using flat field-by-field API. */
export interface PasskeyRegisterOptions {
  /** Base64url-encoded challenge from server. */
  challenge: string;
  /** Relying party domain. */
  rpId: string;
  /** Relying party display name. */
  rpName: string;
  /** Base64url-encoded user ID. */
  userId: string;
  /** User login name. */
  userName: string;
  /** User display name. */
  userDisplayName: string;
  /** Timeout in ms. Default 60000. */
  timeout?: number;
  /** Attestation conveyance. Default `'none'`. */
  attestation?: AttestationConveyancePreference;
  /** Authenticator attachment preference. */
  authenticatorAttachment?: AuthenticatorAttachment;
}

/** Registration response with base64url-encoded fields. */
export interface PasskeyRegistrationResponse {
  /** Credential ID. */
  id: string;
  /** Base64url-encoded raw credential ID. */
  rawId: string;
  type: 'public-key';
  response: {
    /** Base64url-encoded client data JSON. */
    clientDataJSON: string;
    /** Base64url-encoded attestation object. */
    attestationObject: string;
  };
}


/** Authentication options using flat field-by-field API. */
export interface PasskeyAuthenticateOptions {
  /** Base64url-encoded challenge from server. */
  challenge: string;
  /** Relying party domain. */
  rpId: string;
  /** Timeout in ms. Default 60000. */
  timeout?: number;
  /** Allowed credentials for authentication. */
  allowCredentials?: Array<{ id: string; type: 'public-key' }>;
  /** User verification requirement. Default `'preferred'`. */
  userVerification?: UserVerificationRequirement;
}

/** Authentication response with base64url-encoded fields. */
export interface PasskeyAuthenticationResponse {
  /** Credential ID. */
  id: string;
  /** Base64url-encoded raw credential ID. */
  rawId: string;
  type: 'public-key';
  response: {
    /** Base64url-encoded client data JSON. */
    clientDataJSON: string;
    /** Base64url-encoded authenticator data. */
    authenticatorData: string;
    /** Base64url-encoded signature. */
    signature: string;
    /** Base64url-encoded user handle, or null. */
    userHandle: string | null;
  };
}


/** Check whether WebAuthn/passkeys are supported in the current environment. */
export function isSupported(): boolean {
  return (
    typeof globalThis.window !== 'undefined' &&
    typeof (globalThis as unknown as { PublicKeyCredential?: unknown }).PublicKeyCredential !== 'undefined' &&
    typeof (globalThis as { PublicKeyCredential?: { isUserVerifyingPlatformAuthenticatorAvailable?: unknown } }).PublicKeyCredential?.isUserVerifyingPlatformAuthenticatorAvailable === 'function'
  );
}

/**
 * Register a new passkey (flat API).
 *
 * @param options - Flat registration options.
 * @returns Registration response with base64url-encoded fields.
 * @throws {Error} If registration fails or returns an invalid credential type.
 */
export async function register(
  options: PasskeyRegisterOptions,
): Promise<PasskeyRegistrationResponse> {
  const publicKey: PublicKeyCredentialCreationOptions = {
    challenge: base64URLToArrayBuffer(options.challenge),
    rp: { id: options.rpId, name: options.rpName },
    user: {
      id: base64URLToArrayBuffer(options.userId),
      name: options.userName,
      displayName: options.userDisplayName,
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },  // ES256
      { type: 'public-key', alg: -257 }, // RS256
    ],
    timeout: options.timeout ?? 60_000,
    attestation: options.attestation ?? 'none',
    authenticatorSelection: {
      ...(options.authenticatorAttachment !== undefined
        ? { authenticatorAttachment: options.authenticatorAttachment }
        : {}),
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  };

  const credential = await navigator.credentials.create({ publicKey });
  if (!credential || credential.type !== 'public-key') {
    throw new Error('Passkey registration failed: invalid credential type');
  }

  const pkCredential = credential as PublicKeyCredential;
  const response = pkCredential.response as AuthenticatorAttestationResponse;

  return {
    id: pkCredential.id,
    rawId: arrayBufferToBase64URL(pkCredential.rawId),
    type: 'public-key',
    response: {
      clientDataJSON: arrayBufferToBase64URL(response.clientDataJSON),
      attestationObject: arrayBufferToBase64URL(response.attestationObject),
    },
  };
}

/**
 * Register a new passkey using server-format options (base64url strings).
 *
 * Accepts options directly from a WebAuthn server without field remapping.
 *
 * @param options - Server-format registration options.
 * @returns Registration response with base64url-encoded fields.
 * @throws {Error} If registration fails or returns an invalid credential type.
 */
export async function registerWithServerOptions(
  options: ServerRegistrationOptions,
): Promise<PasskeyRegistrationResponse> {
  const publicKey: PublicKeyCredentialCreationOptions = {
    challenge: base64URLToArrayBuffer(options.challenge),
    rp: options.rp,
    user: {
      id: base64URLToArrayBuffer(options.user.id),
      name: options.user.name,
      displayName: options.user.displayName,
    },
    pubKeyCredParams: options.pubKeyCredParams,
    timeout: options.timeout ?? 60_000,
    attestation: options.attestation ?? 'none',
    ...(options.authenticatorSelection !== undefined
      ? { authenticatorSelection: options.authenticatorSelection }
      : {}),
    ...(options.excludeCredentials !== undefined
      ? {
          excludeCredentials: options.excludeCredentials.map((c) => ({
            type: 'public-key' as const,
            id: base64URLToArrayBuffer(c.id),
            ...(c.transports !== undefined ? { transports: c.transports } : {}),
          })),
        }
      : {}),
  };

  const credential = await navigator.credentials.create({ publicKey });
  if (!credential || credential.type !== 'public-key') {
    throw new Error('Passkey registration failed: invalid credential type');
  }

  const pkCredential = credential as PublicKeyCredential;
  const response = pkCredential.response as AuthenticatorAttestationResponse;

  return {
    id: pkCredential.id,
    rawId: arrayBufferToBase64URL(pkCredential.rawId),
    type: 'public-key',
    response: {
      clientDataJSON: arrayBufferToBase64URL(response.clientDataJSON),
      attestationObject: arrayBufferToBase64URL(response.attestationObject),
    },
  };
}

/**
 * Authenticate with a passkey using server-format options (base64url strings).
 *
 * Accepts options directly from a WebAuthn server without field remapping.
 *
 * @param options - Server-format authentication options.
 * @returns Authentication response with base64url-encoded fields.
 * @throws {Error} If authentication fails or returns an invalid credential type.
 */
export async function authenticateWithServerOptions(
  options: ServerAuthenticationOptions,
): Promise<PasskeyAuthenticationResponse> {
  const mappedCredentials = options.allowCredentials?.map((c) => ({
    type: 'public-key' as const,
    id: base64URLToArrayBuffer(c.id),
    ...(c.transports !== undefined ? { transports: c.transports } : {}),
  }));

  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: base64URLToArrayBuffer(options.challenge),
    ...(options.rpId !== undefined ? { rpId: options.rpId } : {}),
    timeout: options.timeout ?? 60_000,
    userVerification: options.userVerification ?? 'preferred',
    ...(mappedCredentials !== undefined ? { allowCredentials: mappedCredentials } : {}),
  };

  const credential = await navigator.credentials.get({ publicKey });
  if (!credential || credential.type !== 'public-key') {
    throw new Error('Passkey authentication failed: invalid credential type');
  }

  const pkCredential = credential as PublicKeyCredential;
  const response = pkCredential.response as AuthenticatorAssertionResponse;

  return {
    id: pkCredential.id,
    rawId: arrayBufferToBase64URL(pkCredential.rawId),
    type: 'public-key',
    response: {
      clientDataJSON: arrayBufferToBase64URL(response.clientDataJSON),
      authenticatorData: arrayBufferToBase64URL(response.authenticatorData),
      signature: arrayBufferToBase64URL(response.signature),
      userHandle: response.userHandle != null ? arrayBufferToBase64URL(response.userHandle) : null,
    },
  };
}

/**
 * Authenticate with a passkey (flat API).
 *
 * @param options - Flat authentication options.
 * @returns Authentication response with base64url-encoded fields.
 * @throws {Error} If authentication fails or returns an invalid credential type.
 */
export async function authenticate(
  options: PasskeyAuthenticateOptions,
): Promise<PasskeyAuthenticationResponse> {
  const allowCredentials: PublicKeyCredentialDescriptor[] | undefined =
    options.allowCredentials?.map((c) => ({
      type: 'public-key' as const,
      id: base64URLToArrayBuffer(c.id),
    }));

  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: base64URLToArrayBuffer(options.challenge),
    rpId: options.rpId,
    timeout: options.timeout ?? 60_000,
    userVerification: options.userVerification ?? 'preferred',
    ...(allowCredentials !== undefined ? { allowCredentials } : {}),
  };

  const credential = await navigator.credentials.get({ publicKey });
  if (!credential || credential.type !== 'public-key') {
    throw new Error('Passkey authentication failed: invalid credential type');
  }

  const pkCredential = credential as PublicKeyCredential;
  const response = pkCredential.response as AuthenticatorAssertionResponse;

  return {
    id: pkCredential.id,
    rawId: arrayBufferToBase64URL(pkCredential.rawId),
    type: 'public-key',
    response: {
      clientDataJSON: arrayBufferToBase64URL(response.clientDataJSON),
      authenticatorData: arrayBufferToBase64URL(response.authenticatorData),
      signature: arrayBufferToBase64URL(response.signature),
      userHandle: response.userHandle != null ? arrayBufferToBase64URL(response.userHandle) : null,
    },
  };
}
