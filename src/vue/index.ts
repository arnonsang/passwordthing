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
  value: Ref<string>;
  setValue: (val: string) => void;
  isValid: ComputedRef<boolean>;
  failedRules: ComputedRef<ValidationResult['failedRules']>;
  strength: ComputedRef<StrengthResult | null>;
  breachStatus: Ref<BreachStatus | null>;
  generateNew: (options: GeneratorOptions) => void;
}

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
  isSupported: boolean;
  isAuthenticating: Ref<boolean>;
  error: Ref<Error | null>;
  register: (options: PasskeyRegisterOptions) => Promise<PasskeyRegistrationResponse | null>;
  authenticate: (options: PasskeyAuthenticateOptions) => Promise<PasskeyAuthenticationResponse | null>;
  registerWithServerOptions: (options: ServerRegistrationOptions) => Promise<PasskeyRegistrationResponse | null>;
  authenticateWithServerOptions: (options: ServerAuthenticationOptions) => Promise<PasskeyAuthenticationResponse | null>;
}

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
