/**
 * @module strength/presets
 *
 * Strength scoring presets mapping entropy bit thresholds to
 * 0–4 scores. Each entry is a tuple of 4 thresholds:
 * `[score0→1, score1→2, score2→3, score3→4]`.
 *
 * - `BASIC` — Relaxed thresholds suitable for general use.
 * - `NIST_MODERN` — Aligned with NIST SP 800-63B guidelines.
 * - `OWASP_STRICT` — Strict thresholds per OWASP ASVS.
 */

export type StrengthPreset = 'OWASP_STRICT' | 'NIST_MODERN' | 'BASIC';

// Entropy bit thresholds: [score0→1, score1→2, score2→3, score3→4]
export const PRESET_THRESHOLDS: Record<StrengthPreset, readonly [number, number, number, number]> =
  {
    BASIC: [28, 36, 60, 80],
    NIST_MODERN: [20, 30, 50, 70],
    OWASP_STRICT: [40, 60, 80, 100],
  };
