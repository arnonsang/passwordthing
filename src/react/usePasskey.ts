import { useState, useCallback } from 'react';
import type { PasskeyRegisterOptions, PasskeyRegistrationResponse } from '../passkey/passkey.js';
import type { PasskeyAuthenticateOptions, PasskeyAuthenticationResponse } from '../passkey/passkey.js';
import type { ServerRegistrationOptions, ServerAuthenticationOptions } from '../passkey/passkey.js';
import { isSupported, register, authenticate, registerWithServerOptions, authenticateWithServerOptions } from '../passkey/passkey.js';

export interface UsePasskeyReturn {
  isSupported: boolean;
  isAuthenticating: boolean;
  error: Error | null;
  register: (options: PasskeyRegisterOptions) => Promise<PasskeyRegistrationResponse | null>;
  authenticate: (options: PasskeyAuthenticateOptions) => Promise<PasskeyAuthenticationResponse | null>;
  registerWithServerOptions: (options: ServerRegistrationOptions) => Promise<PasskeyRegistrationResponse | null>;
  authenticateWithServerOptions: (options: ServerAuthenticationOptions) => Promise<PasskeyAuthenticationResponse | null>;
}

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
