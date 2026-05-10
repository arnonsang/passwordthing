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
  value: string;
  setValue: (val: string) => void;
  isValid: boolean;
  failedRules: ValidationResult['failedRules'];
  strength: StrengthResult | null;
  breachStatus: BreachStatus | null;
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
