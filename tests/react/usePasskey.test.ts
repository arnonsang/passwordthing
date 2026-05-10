import { describe, expect, test, vi, afterEach, beforeAll } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { usePasskey } from '../../src/react/usePasskey.js';
import { arrayBufferToBase64URL } from '../../src/passkey/utils.js';

function makeBuffer(bytes: number[]): ArrayBuffer {
  return new Uint8Array(bytes).buffer;
}

const CHALLENGE = arrayBufferToBase64URL(makeBuffer([0, 1, 2, 3]));
const USER_ID = arrayBufferToBase64URL(makeBuffer([9, 8, 7]));

// Stub navigator.credentials for happy-dom which doesn't include it
beforeAll(() => {
  Object.defineProperty(globalThis.navigator, 'credentials', {
    value: { create: vi.fn(), get: vi.fn() },
    writable: true,
    configurable: true,
  });
});

const MOCK_REG_CREDENTIAL = {
  id: 'cred-id',
  rawId: makeBuffer([1, 2, 3]),
  type: 'public-key',
  response: {
    clientDataJSON: makeBuffer([1]),
    attestationObject: makeBuffer([2]),
  },
} as unknown as PublicKeyCredential;

const MOCK_AUTH_CREDENTIAL = {
  id: 'cred-id',
  rawId: makeBuffer([1, 2, 3]),
  type: 'public-key',
  response: {
    clientDataJSON: makeBuffer([1]),
    authenticatorData: makeBuffer([2]),
    signature: makeBuffer([3]),
    userHandle: null,
  },
} as unknown as PublicKeyCredential;

describe('usePasskey – isSupported', () => {
  test('exposes isSupported flag', () => {
    const { result } = renderHook(() => usePasskey());
    expect(typeof result.current.isSupported).toBe('boolean');
  });
});

describe('usePasskey – register', () => {
  afterEach(() => vi.restoreAllMocks());

  test('sets isAuthenticating during register', async () => {
    let resolveFn!: (v: Credential | null) => void;
    vi.spyOn(navigator.credentials, 'create').mockImplementation(
      () => new Promise<Credential | null>((res) => { resolveFn = res; }),
    );

    const { result } = renderHook(() => usePasskey());

    let registerPromise!: Promise<unknown>;
    act(() => {
      registerPromise = result.current.register({
        challenge: CHALLENGE,
        rpId: 'example.com',
        rpName: 'Example',
        userId: USER_ID,
        userName: 'alice',
        userDisplayName: 'Alice',
      });
    });

    expect(result.current.isAuthenticating).toBe(true);

    await act(async () => {
      resolveFn(MOCK_REG_CREDENTIAL);
      await registerPromise;
    });

    expect(result.current.isAuthenticating).toBe(false);
    expect(result.current.error).toBeNull();
  });

  test('sets error and returns null on failure', async () => {
    vi.spyOn(navigator.credentials, 'create').mockRejectedValue(
      new DOMException('User cancelled', 'NotAllowedError'),
    );

    const { result } = renderHook(() => usePasskey());
    let returnValue: unknown;

    await act(async () => {
      returnValue = await result.current.register({
        challenge: CHALLENGE,
        rpId: 'example.com',
        rpName: 'Example',
        userId: USER_ID,
        userName: 'alice',
        userDisplayName: 'Alice',
      });
    });

    expect(returnValue).toBeNull();
    expect(result.current.error).toBeInstanceOf(Error);
    expect(result.current.isAuthenticating).toBe(false);
  });
});

describe('usePasskey – authenticate', () => {
  afterEach(() => vi.restoreAllMocks());

  test('returns auth response on success', async () => {
    vi.spyOn(navigator.credentials, 'get').mockResolvedValue(MOCK_AUTH_CREDENTIAL);

    const { result } = renderHook(() => usePasskey());
    let response: unknown;

    await act(async () => {
      response = await result.current.authenticate({
        challenge: CHALLENGE,
        rpId: 'example.com',
      });
    });

    expect(response).not.toBeNull();
    expect(result.current.isAuthenticating).toBe(false);
  });
});
