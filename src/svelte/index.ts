/**
 * @module svelte
 *
 * Svelte 5 stores for password management and passkey
 * authentication. Uses `writable` and `derived` stores
 * for reactive state.
 *
 * @example
 * ```ts
 * import { usePassword, usePasskey } from 'passwordthing/svelte';
 * ```
 */

import { writable, derived, get } from 'svelte/store';
import type { Readable, Writable } from 'svelte/store';
import type { ValidationOptions, ValidationResult } from '../core/validate.js';
import { validate } from '../core/validate.js';
import type { GeneratorOptions } from '../core/generate.js';
import { generate } from '../core/generate.js';
import type { StrengthPreset, StrengthResult } from '../strength/entropy.js';
import { evaluateStrength } from '../strength/entropy.js';
import type { BreachResult } from '../breach/check.js';
import { checkBreach } from '../breach/check.js';
import type {
  PasskeyRegisterOptions,
  PasskeyRegistrationResponse,
  PasskeyAuthenticateOptions,
  PasskeyAuthenticationResponse,
  ServerRegistrationOptions,
  ServerAuthenticationOptions,
} from '../passkey/passkey.js';
import {
  isSupported,
  register,
  authenticate,
  registerWithServerOptions,
  authenticateWithServerOptions,
} from '../passkey/passkey.js';

export interface UsePasswordConfig {
  /** Validation rules (min, max, digits, etc.). */
  rules?: ValidationOptions;
  /** Strength scoring preset. Default `'BASIC'`. */
  strengthPreset?: StrengthPreset;
  /** Enable Have I Been Pwned breach checking. Default `false`. */
  enableBreachCheck?: boolean;
  /** Debounce delay in ms for breach lookups. Default 500. */
  breachDebounceMs?: number;
  /** Known user data to penalize in strength evaluation. */
  userInputs?: string[];
}

export interface BreachStatus {
  /** Whether a breach check is in progress. */
  loading: boolean;
  /** Whether the password was found in known breaches. */
  isPwned: boolean;
  /** Number of occurrences across breaches. */
  occurrences: number;
}

export interface UsePasswordReturn {
  /** Current password value (writable store). */
  value: Writable<string>;
  /** Update password value (triggers validation, strength, breach). */
  setValue: (val: string) => void;
  /** Whether the password passes all validation rules (derived store). */
  isValid: Readable<boolean>;
  /** List of failed validation rules with messages (derived store). */
  failedRules: Readable<ValidationResult['failedRules']>;
  /** Strength evaluation result, or null if empty (derived store). */
  strength: Readable<StrengthResult | null>;
  /** Breach check status, or null if disabled (readable store). */
  breachStatus: Readable<BreachStatus | null>;
  /** Generate a new password with the given generator options. */
  generateNew: (options: GeneratorOptions) => void;
  /** Clean up the debounce timer. Call on component destroy. */
  destroy: () => void;
}

/**
 * Svelte store factory for password management.
 *
 * @param config - Optional configuration.
 * @returns Password stores and actions.
 */
export function usePassword(config: UsePasswordConfig = {}): UsePasswordReturn {
  const {
    rules,
    strengthPreset = 'BASIC',
    enableBreachCheck = false,
    breachDebounceMs = 500,
    userInputs,
  } = config;

  const value = writable('');
  const breachStatus = writable<BreachStatus | null>(null);
  let debounceTimer: ReturnType<typeof setTimeout> | null = null;

  const EMPTY_VALIDATION: ValidationResult = { isValid: true, failedRules: [] };
  const validation = derived<typeof value, ValidationResult>(value, ($value) =>
    $value.length > 0 ? validate($value, rules ?? {}) : EMPTY_VALIDATION,
  );

  const strength = derived<typeof value, StrengthResult | null>(value, ($value) =>
    $value.length > 0
      ? evaluateStrength($value, {
          preset: strengthPreset,
          ...(userInputs !== undefined ? { userInputs } : {}),
        })
      : null,
  );

  const setValue = (val: string) => {
    value.set(val);

    if (!enableBreachCheck || val.length === 0) {
      breachStatus.set(null);
      return;
    }

    if (debounceTimer !== null) clearTimeout(debounceTimer);
    const current = get(breachStatus);
    breachStatus.set(
      current !== null
        ? { ...current, loading: true }
        : { loading: true, isPwned: false, occurrences: 0 },
    );

    debounceTimer = setTimeout(() => {
      checkBreach(val)
        .then((result: BreachResult) => {
          breachStatus.set({ loading: false, isPwned: result.isPwned, occurrences: result.occurrences });
        })
        .catch(() => {
          breachStatus.set({ loading: false, isPwned: false, occurrences: 0 });
        });
    }, breachDebounceMs);
  };

  const generateNew = (options: GeneratorOptions) => {
    setValue(generate(options));
  };

  const destroy = () => {
    if (debounceTimer !== null) clearTimeout(debounceTimer);
  };

  return {
    value,
    setValue,
    isValid: derived(validation, ($v) => $v.isValid),
    failedRules: derived(validation, ($v) => $v.failedRules),
    strength,
    breachStatus,
    generateNew,
    destroy,
  };
}

export interface UsePasskeyReturn {
  /** Whether passkeys are supported in the current environment. */
  isSupported: boolean;
  /** Whether an authentication/registration operation is in progress (readable store). */
  isAuthenticating: Readable<boolean>;
  /** Last error, or null (readable store). */
  error: Readable<Error | null>;
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
 * Svelte store factory for passkey management.
 *
 * @returns Passkey stores and wrapped functions.
 */
export function usePasskey(): UsePasskeyReturn {
  const isAuthenticatingStore = writable(false);
  const errorStore = writable<Error | null>(null);

  function wrap<TOptions, TResult>(fn: (opts: TOptions) => Promise<TResult>) {
    return async (options: TOptions): Promise<TResult | null> => {
      isAuthenticatingStore.set(true);
      errorStore.set(null);
      try {
        return await fn(options);
      } catch (err) {
        errorStore.set(err instanceof Error ? err : new Error(String(err)));
        return null;
      } finally {
        isAuthenticatingStore.set(false);
      }
    };
  }

  return {
    isSupported: isSupported(),
    isAuthenticating: { subscribe: isAuthenticatingStore.subscribe },
    error: { subscribe: errorStore.subscribe },
    register: wrap(register),
    authenticate: wrap(authenticate),
    registerWithServerOptions: wrap(registerWithServerOptions),
    authenticateWithServerOptions: wrap(authenticateWithServerOptions),
  };
}
