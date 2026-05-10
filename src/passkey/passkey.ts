import { base64URLToArrayBuffer, arrayBufferToBase64URL } from './utils.js';


export interface PasskeyRegisterOptions {
  challenge: string;          // base64url challenge from server
  rpId: string;               // relying party domain
  rpName: string;
  userId: string;             // base64url user id
  userName: string;
  userDisplayName: string;
  timeout?: number;
  attestation?: AttestationConveyancePreference;
  authenticatorAttachment?: AuthenticatorAttachment;
}

export interface PasskeyRegistrationResponse {
  id: string;
  rawId: string;
  type: 'public-key';
  response: {
    clientDataJSON: string;
    attestationObject: string;
  };
}


export interface PasskeyAuthenticateOptions {
  challenge: string;          // base64url challenge from server
  rpId: string;
  timeout?: number;
  allowCredentials?: Array<{ id: string; type: 'public-key' }>;
  userVerification?: UserVerificationRequirement;
}

export interface PasskeyAuthenticationResponse {
  id: string;
  rawId: string;
  type: 'public-key';
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle: string | null;
  };
}


export function isSupported(): boolean {
  return (
    typeof globalThis.window !== 'undefined' &&
    typeof (globalThis as unknown as { PublicKeyCredential?: unknown }).PublicKeyCredential !== 'undefined' &&
    typeof (globalThis as { PublicKeyCredential?: { isUserVerifyingPlatformAuthenticatorAvailable?: unknown } }).PublicKeyCredential?.isUserVerifyingPlatformAuthenticatorAvailable === 'function'
  );
}

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
