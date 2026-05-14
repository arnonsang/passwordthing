/**
 * @module react/usePasskey
 *
 * React hook for passkey registration and authentication.
 * Wraps the passkey primitives with loading/error state management.
 *
 * @example
 * ```tsx
 * import { usePasskey } from 'passwordthing/react';
 *
 * function PasskeyButton() {
 *   const { isSupported, register, isAuthenticating, error } = usePasskey();
 *   if (!isSupported) return <p>Passkeys not supported</p>;
 *   return <button onClick={() => register(options)}>Register</button>;
 * }
 * ```
 */

import { useState, useCallback } from 'react';
import type { PasskeyRegisterOptions, PasskeyRegistrationResponse } from '../passkey/passkey.js';
import type { PasskeyAuthenticateOptions, PasskeyAuthenticationResponse } from '../passkey/passkey.js';
import type { ServerRegistrationOptions, ServerAuthenticationOptions } from '../passkey/passkey.js';
import { isSupported, register, authenticate, registerWithServerOptions, authenticateWithServerOptions } from '../passkey/passkey.js';

export interface UsePasskeyReturn {
  /** Whether passkeys are supported in the current environment. */
  isSupported: boolean;
  /** Whether an authentication/registration operation is in progress. */
  isAuthenticating: boolean;
  /** Last error, or null. */
  error: Error | null;
  /** Register a new passkey (flat API). Returns null on error. */
  register: (options: PasskeyRegisterOptions) => Promise<PasskeyRegistrationResponse | null>;
  /** Authenticate with a passkey (flat API). Returns null on error. */
  authenticate: (options: PasskeyAuthenticateOptions) => Promise<PasskeyAuthenticationResponse | null>;
  /** Register a new passkey (server-options API). Returns null on error. */
  registerWithServerOptions: (options: ServerRegistrationOptions) => Promise<PasskeyRegistrationResponse | null>;
  /** Authenticate with a passkey (server-options API). Returns null on error. */
  authenticateWithServerOptions: (options: ServerAuthenticationOptions) => Promise<PasskeyAuthenticationResponse | null>;
}

/**
 * React hook for passkey management.
 *
 * Provides reactive `isAuthenticating` and `error` state, and
 * wraps passkey primitives so they catch errors and set state
 * rather than throwing.
 *
 * @returns Passkey state and wrapped functions.
 */
export function usePasskey(): UsePasskeyReturn {
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const supported = isSupported();

  const handleRegister = useCallback(
    async (options: PasskeyRegisterOptions): Promise<PasskeyRegistrationResponse | null> => {
      setIsAuthenticating(true);
      setError(null);
      try {
        const result = await register(options);
        return result;
      } catch (err) {
        setError(err instanceof Error ? err : new Error(String(err)));
        return null;
      } finally {
        setIsAuthenticating(false);
      }
    },
    [],
  );

  const handleAuthenticate = useCallback(
    async (options: PasskeyAuthenticateOptions): Promise<PasskeyAuthenticationResponse | null> => {
      setIsAuthenticating(true);
      setError(null);
      try {
        const result = await authenticate(options);
        return result;
      } catch (err) {
        setError(err instanceof Error ? err : new Error(String(err)));
        return null;
      } finally {
        setIsAuthenticating(false);
      }
    },
    [],
  );

  const handleRegisterWithServerOptions = useCallback(
    async (options: ServerRegistrationOptions): Promise<PasskeyRegistrationResponse | null> => {
      setIsAuthenticating(true);
      setError(null);
      try {
        const result = await registerWithServerOptions(options);
        return result;
      } catch (err) {
        setError(err instanceof Error ? err : new Error(String(err)));
        return null;
      } finally {
        setIsAuthenticating(false);
      }
    },
    [],
  );

  const handleAuthenticateWithServerOptions = useCallback(
    async (options: ServerAuthenticationOptions): Promise<PasskeyAuthenticationResponse | null> => {
      setIsAuthenticating(true);
      setError(null);
      try {
        const result = await authenticateWithServerOptions(options);
        return result;
      } catch (err) {
        setError(err instanceof Error ? err : new Error(String(err)));
        return null;
      } finally {
        setIsAuthenticating(false);
      }
    },
    [],
  );

  return {
    isSupported: supported,
    isAuthenticating,
    error,
    register: handleRegister,
    authenticate: handleAuthenticate,
    registerWithServerOptions: handleRegisterWithServerOptions,
    authenticateWithServerOptions: handleAuthenticateWithServerOptions,
  };
}
