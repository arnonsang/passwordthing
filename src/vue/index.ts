/**
 * @module vue
 *
 * Vue 3 composables for password management and passkey
 * authentication. Uses `ref`, `computed`, and `onUnmounted`
 * for reactive state.
 *
 * @example
 * ```ts
 * import { usePassword, usePasskey } from 'passwordthing/vue';
 * ```
 */

import { ref, computed, onUnmounted } from 'vue';
import type { Ref, ComputedRef } from 'vue';
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
  /** Current password value (reactive). */
  value: Ref<string>;
  /** Update password value (triggers validation, strength, breach). */
  setValue: (val: string) => void;
  /** Whether the password passes all validation rules (computed). */
  isValid: ComputedRef<boolean>;
  /** List of failed validation rules with messages (computed). */
  failedRules: ComputedRef<ValidationResult['failedRules']>;
  /** Strength evaluation result, or null if empty (computed). */
  strength: ComputedRef<StrengthResult | null>;
  /** Breach check status, or null if disabled (reactive). */
  breachStatus: Ref<BreachStatus | null>;
  /** Generate a new password with the given generator options. */
  generateNew: (options: GeneratorOptions) => void;
}

/**
 * Vue composable for password management.
 *
 * @param config - Optional configuration.
 * @returns Password reactive state and actions.
 */
export function usePassword(config: UsePasswordConfig = {}): UsePasswordReturn {
  const {
    rules,
    strengthPreset = 'BASIC',
    enableBreachCheck = false,
    breachDebounceMs = 500,
    userInputs,
  } = config;

  const value = ref('');
  const breachStatus = ref<BreachStatus | null>(null);
  let debounceTimer: ReturnType<typeof setTimeout> | null = null;

  const validation = computed<ValidationResult>(() =>
    value.value.length > 0 ? validate(value.value, rules ?? {}) : { isValid: true, failedRules: [] },
  );

  const strength = computed<StrengthResult | null>(() =>
    value.value.length > 0
      ? evaluateStrength(value.value, {
          preset: strengthPreset,
          ...(userInputs !== undefined ? { userInputs } : {}),
        })
      : null,
  );

  const setValue = (val: string) => {
    value.value = val;

    if (!enableBreachCheck || val.length === 0) {
      breachStatus.value = null;
      return;
    }

    if (debounceTimer !== null) clearTimeout(debounceTimer);
    breachStatus.value =
      breachStatus.value !== null
        ? { ...breachStatus.value, loading: true }
        : { loading: true, isPwned: false, occurrences: 0 };

    debounceTimer = setTimeout(() => {
      checkBreach(val)
        .then((result: BreachResult) => {
          breachStatus.value = { loading: false, isPwned: result.isPwned, occurrences: result.occurrences };
        })
        .catch(() => {
          breachStatus.value = { loading: false, isPwned: false, occurrences: 0 };
        });
    }, breachDebounceMs);
  };

  const generateNew = (options: GeneratorOptions) => {
    setValue(generate(options));
  };

  onUnmounted(() => {
    if (debounceTimer !== null) clearTimeout(debounceTimer);
  });

  return {
    value,
    setValue,
    isValid: computed(() => validation.value.isValid),
    failedRules: computed(() => validation.value.failedRules),
    strength,
    breachStatus,
    generateNew,
  };
}

export interface UsePasskeyReturn {
  /** Whether passkeys are supported in the current environment. */
  isSupported: boolean;
  /** Whether an authentication/registration operation is in progress (reactive). */
  isAuthenticating: Ref<boolean>;
  /** Last error, or null (reactive). */
  error: Ref<Error | null>;
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
 * Vue composable for passkey management.
 *
 * @returns Passkey reactive state and wrapped functions.
 */
export function usePasskey(): UsePasskeyReturn {
  const isAuthenticating = ref(false);
  const error = ref<Error | null>(null);

  const wrap = <TOptions, TResult>(fn: (opts: TOptions) => Promise<TResult>) =>
    async (options: TOptions): Promise<TResult | null> => {
      isAuthenticating.value = true;
      error.value = null;
      try {
        return await fn(options);
      } catch (err) {
        error.value = err instanceof Error ? err : new Error(String(err));
        return null;
      } finally {
        isAuthenticating.value = false;
      }
    };

  return {
    isSupported: isSupported(),
    isAuthenticating,
    error,
    register: wrap(register),
    authenticate: wrap(authenticate),
    registerWithServerOptions: wrap(registerWithServerOptions),
    authenticateWithServerOptions: wrap(authenticateWithServerOptions),
  };
}
