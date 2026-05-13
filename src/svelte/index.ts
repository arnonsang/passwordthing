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
  rules?: ValidationOptions;
  strengthPreset?: StrengthPreset;
  enableBreachCheck?: boolean;
  breachDebounceMs?: number;
  userInputs?: string[];
}

export interface BreachStatus {
  loading: boolean;
  isPwned: boolean;
  occurrences: number;
}

export interface UsePasswordReturn {
  value: Writable<string>;
  setValue: (val: string) => void;
  isValid: Readable<boolean>;
  failedRules: Readable<ValidationResult['failedRules']>;
  strength: Readable<StrengthResult | null>;
  breachStatus: Readable<BreachStatus | null>;
  generateNew: (options: GeneratorOptions) => void;
  destroy: () => void;
}

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
  isSupported: boolean;
  isAuthenticating: Readable<boolean>;
  error: Readable<Error | null>;
  register: (options: PasskeyRegisterOptions) => Promise<PasskeyRegistrationResponse | null>;
  authenticate: (options: PasskeyAuthenticateOptions) => Promise<PasskeyAuthenticationResponse | null>;
  registerWithServerOptions: (options: ServerRegistrationOptions) => Promise<PasskeyRegistrationResponse | null>;
  authenticateWithServerOptions: (options: ServerAuthenticationOptions) => Promise<PasskeyAuthenticationResponse | null>;
}

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
