/**
 * @module react/usePassword
 *
 * React hook that combines password generation, validation,
 * strength evaluation, and breach checking with debounced
 * HIBP lookups.
 *
 * @example
 * ```tsx
 * import { usePassword } from 'passwordthing/react';
 *
 * function SignUpForm() {
 *   const { value, setValue, isValid, strength, breachStatus, generateNew } =
 *     usePassword({ rules: { min: 8, digits: 1 }, enableBreachCheck: true });
 *
 *   return <input value={value} onChange={e => setValue(e.target.value)} />;
 * }
 * ```
 */

import { useState, useCallback, useRef, useMemo } from 'react';
import type { ValidationOptions, ValidationResult } from '../core/validate.js';
import { validate } from '../core/validate.js';
import type { GeneratorOptions } from '../core/generate.js';
import { generate } from '../core/generate.js';
import type { StrengthPreset, StrengthResult } from '../strength/entropy.js';
import { evaluateStrength } from '../strength/entropy.js';
import type { BreachResult } from '../breach/check.js';
import { checkBreach } from '../breach/check.js';

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
  /** Current password value. */
  value: string;
  /** Update password value (triggers validation, strength, breach). */
  setValue: (val: string) => void;
  /** Whether the password passes all validation rules. */
  isValid: boolean;
  /** List of failed validation rules with messages. */
  failedRules: ValidationResult['failedRules'];
  /** Strength evaluation result, or null if value is empty. */
  strength: StrengthResult | null;
  /** Breach check status, or null if breach check is disabled. */
  breachStatus: BreachStatus | null;
  /** Generate a new password with the given generator options. */
  generateNew: (options: GeneratorOptions) => void;
}

/**
 * React hook for password management.
 *
 * Integrates validation, strength evaluation, and optional
 * debounced HIBP breach checking into a single reactive hook.
 *
 * @param config - Optional configuration.
 * @returns Password state and actions.
 */
export function usePassword(config: UsePasswordConfig = {}): UsePasswordReturn {
  const {
    rules,
    strengthPreset = 'BASIC',
    enableBreachCheck = false,
    breachDebounceMs = 500,
    userInputs,
  } = config;

  const [value, setValueState] = useState('');
  const [breachStatus, setBreachStatus] = useState<BreachStatus | null>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const validation = useMemo<ValidationResult>(
    () => (value.length > 0 ? validate(value, rules ?? {}) : { isValid: true, failedRules: [] }),
    [value, rules],
  );

  const strength = useMemo<StrengthResult | null>(
    () => (value.length > 0 ? evaluateStrength(value, { preset: strengthPreset, ...(userInputs !== undefined ? { userInputs } : {}) }) : null),
    [value, strengthPreset, userInputs],
  );

  const setValue = useCallback(
    (val: string) => {
      setValueState(val);

      if (!enableBreachCheck || val.length === 0) {
        setBreachStatus(null);
        return;
      }

      if (debounceRef.current !== null) clearTimeout(debounceRef.current);
      setBreachStatus((prev) => (prev !== null ? { ...prev, loading: true } : { loading: true, isPwned: false, occurrences: 0 }));

      debounceRef.current = setTimeout(() => {
        checkBreach(val)
          .then((result: BreachResult) => {
            setBreachStatus({ loading: false, isPwned: result.isPwned, occurrences: result.occurrences });
          })
          .catch(() => {
            setBreachStatus({ loading: false, isPwned: false, occurrences: 0 });
          });
      }, breachDebounceMs);
    },
    [enableBreachCheck, breachDebounceMs],
  );

  const generateNew = useCallback((options: GeneratorOptions) => {
    const generated = generate(options);
    setValue(generated);
  }, [setValue]);

  return {
    value,
    setValue,
    isValid: validation.isValid,
    failedRules: validation.failedRules,
    strength,
    breachStatus,
    generateNew,
  };
}
