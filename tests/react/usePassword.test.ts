import { describe, expect, test, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { usePassword } from '../../src/react/usePassword.js';

// Mock checkBreach to avoid real network calls and async complexity in debounce tests
vi.mock('../../src/breach/check.js', () => ({
  checkBreach: vi.fn().mockResolvedValue({ isPwned: false, occurrences: 0 }),
}));

import { checkBreach } from '../../src/breach/check.js';
const mockCheckBreach = vi.mocked(checkBreach);

describe('usePassword – basic state management', () => {
  test('initial state', () => {
    const { result } = renderHook(() => usePassword());
    expect(result.current.value).toBe('');
    expect(result.current.isValid).toBe(true);
    expect(result.current.strength).toBeNull();
    expect(result.current.breachStatus).toBeNull();
  });

  test('setValue updates value and strength', () => {
    const { result } = renderHook(() => usePassword());
    act(() => result.current.setValue('StrongP@ssword123'));
    expect(result.current.value).toBe('StrongP@ssword123');
    expect(result.current.strength).not.toBeNull();
  });

  test('validation rules are applied', () => {
    const { result } = renderHook(() => usePassword({ rules: { min: 12 } }));
    act(() => result.current.setValue('short'));
    expect(result.current.isValid).toBe(false);
    expect(result.current.failedRules.length).toBeGreaterThan(0);
  });
});

describe('usePassword – breach check debounce', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    mockCheckBreach.mockClear();
    mockCheckBreach.mockResolvedValue({ isPwned: false, occurrences: 0 });
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  test('breach check is NOT triggered before debounce elapses', () => {
    const { result } = renderHook(() =>
      usePassword({ enableBreachCheck: true, breachDebounceMs: 500 }),
    );

    act(() => result.current.setValue('Password1!'));
    // Timer not elapsed yet, checkBreach must not have been called
    expect(mockCheckBreach).not.toHaveBeenCalled();
    expect(result.current.breachStatus?.loading).toBe(true);
  });

  test('breach check fires after debounce elapses', async () => {
    const { result } = renderHook(() =>
      usePassword({ enableBreachCheck: true, breachDebounceMs: 500 }),
    );

    act(() => result.current.setValue('SomeUniquePass99!'));

    await act(async () => {
      vi.advanceTimersByTime(600);
      // flush microtasks so the mock promise resolves
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(mockCheckBreach).toHaveBeenCalledTimes(1);
    expect(result.current.breachStatus?.loading).toBe(false);
    expect(result.current.breachStatus?.isPwned).toBe(false);
  });

  test('rapid typing cancels previous debounce', async () => {
    const { result } = renderHook(() =>
      usePassword({ enableBreachCheck: true, breachDebounceMs: 500 }),
    );

    act(() => result.current.setValue('type1'));
    act(() => { vi.advanceTimersByTime(200); });
    act(() => result.current.setValue('type2'));
    act(() => { vi.advanceTimersByTime(200); });
    act(() => result.current.setValue('type3'));

    await act(async () => {
      vi.advanceTimersByTime(600);
      await Promise.resolve();
      await Promise.resolve();
    });

    // Only the last keystroke should trigger a fetch
    expect(mockCheckBreach).toHaveBeenCalledTimes(1);
    expect(mockCheckBreach).toHaveBeenCalledWith('type3');
  });
});

describe('usePassword – generateNew', () => {
  test('generates and sets a new password', () => {
    const { result } = renderHook(() => usePassword());
    act(() => result.current.generateNew({ length: 16 }));
    expect(result.current.value.length).toBe(16);
    expect(result.current.strength).not.toBeNull();
  });
});
