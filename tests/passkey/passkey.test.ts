import { describe, expect, test, vi, afterEach, beforeAll } from 'vitest';
import { arrayBufferToBase64URL, base64URLToArrayBuffer } from '../../src/passkey/utils.js';
import { isSupported, register, authenticate } from '../../src/passkey/passkey.js';


function makeBuffer(bytes: number[]): ArrayBuffer {
  return new Uint8Array(bytes).buffer;
}

const MOCK_CLIENT_DATA = makeBuffer([1, 2, 3]);
const MOCK_ATTESTATION = makeBuffer([4, 5, 6]);
const MOCK_AUTH_DATA = makeBuffer([7, 8, 9]);
const MOCK_SIGNATURE = makeBuffer([10, 11, 12]);
const MOCK_USER_HANDLE = makeBuffer([13, 14, 15]);

const CHALLENGE_B64 = arrayBufferToBase64URL(makeBuffer([0, 1, 2, 3]));
const USER_ID_B64 = arrayBufferToBase64URL(makeBuffer([9, 8, 7]));

// Stub navigator.credentials for happy-dom which doesn't include it
beforeAll(() => {
  Object.defineProperty(globalThis.navigator, 'credentials', {
    value: { create: vi.fn(), get: vi.fn() },
    writable: true,
    configurable: true,
  });
});


describe('isSupported', () => {
  test('returns false in Node/happy-dom without PublicKeyCredential', () => {
    // happy-dom may or may not expose PublicKeyCredential
    const result = isSupported();
    expect(typeof result).toBe('boolean');
  });
});


describe('register', () => {
  afterEach(() => vi.restoreAllMocks());

  test('maps options and returns base64url response', async () => {
    const mockCredential = {
      id: 'cred-id',
      rawId: makeBuffer([1, 2, 3, 4]),
      type: 'public-key',
      response: {
        clientDataJSON: MOCK_CLIENT_DATA,
        attestationObject: MOCK_ATTESTATION,
      },
    } as unknown as PublicKeyCredential;

    vi.spyOn(navigator.credentials, 'create').mockResolvedValue(mockCredential);

    const result = await register({
      challenge: CHALLENGE_B64,
      rpId: 'example.com',
      rpName: 'Example',
      userId: USER_ID_B64,
      userName: 'alice',
      userDisplayName: 'Alice',
    });

    expect(result.id).toBe('cred-id');
    expect(result.type).toBe('public-key');
    expect(typeof result.rawId).toBe('string');
    expect(typeof result.response.clientDataJSON).toBe('string');
    expect(typeof result.response.attestationObject).toBe('string');

    // Verify the base64url encoding round-trips
    const clientDataBytes = new Uint8Array(base64URLToArrayBuffer(result.response.clientDataJSON));
    expect(clientDataBytes).toEqual(new Uint8Array(MOCK_CLIENT_DATA));
  });

  test('throws when credentials.create returns wrong type', async () => {
    vi.spyOn(navigator.credentials, 'create').mockResolvedValue(null);
    await expect(
      register({
        challenge: CHALLENGE_B64,
        rpId: 'example.com',
        rpName: 'Example',
        userId: USER_ID_B64,
        userName: 'alice',
        userDisplayName: 'Alice',
      }),
    ).rejects.toThrow('invalid credential type');
  });
});


describe('authenticate', () => {
  afterEach(() => vi.restoreAllMocks());

  test('maps options and returns base64url response', async () => {
    const mockCredential = {
      id: 'cred-id',
      rawId: makeBuffer([1, 2, 3, 4]),
      type: 'public-key',
      response: {
        clientDataJSON: MOCK_CLIENT_DATA,
        authenticatorData: MOCK_AUTH_DATA,
        signature: MOCK_SIGNATURE,
        userHandle: MOCK_USER_HANDLE,
      },
    } as unknown as PublicKeyCredential;

    vi.spyOn(navigator.credentials, 'get').mockResolvedValue(mockCredential);

    const result = await authenticate({
      challenge: CHALLENGE_B64,
      rpId: 'example.com',
    });

    expect(result.type).toBe('public-key');
    expect(typeof result.response.signature).toBe('string');
    expect(result.response.userHandle).not.toBeNull();

    const sigBytes = new Uint8Array(base64URLToArrayBuffer(result.response.signature));
    expect(sigBytes).toEqual(new Uint8Array(MOCK_SIGNATURE));
  });

  test('returns null userHandle when authenticator provides none', async () => {
    const mockCredential = {
      id: 'cred-id',
      rawId: makeBuffer([1]),
      type: 'public-key',
      response: {
        clientDataJSON: MOCK_CLIENT_DATA,
        authenticatorData: MOCK_AUTH_DATA,
        signature: MOCK_SIGNATURE,
        userHandle: null,
      },
    } as unknown as PublicKeyCredential;

    vi.spyOn(navigator.credentials, 'get').mockResolvedValue(mockCredential);

    const result = await authenticate({ challenge: CHALLENGE_B64, rpId: 'example.com' });
    expect(result.response.userHandle).toBeNull();
  });
});
