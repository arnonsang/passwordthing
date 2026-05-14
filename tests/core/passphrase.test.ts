import { describe, expect, test } from 'vitest';
import { generatePassphrase } from '../../src/core/passphrase.js';

describe('generatePassphrase – default options', () => {
  test('returns 4-word hyphen-separated string', () => {
    const p = generatePassphrase();
    const parts = p.split('-');
    expect(parts).toHaveLength(4);
    for (const w of parts) expect(w.length).toBeGreaterThan(0);
  });

  test('all lowercase by default', () => {
    const p = generatePassphrase();
    expect(p).toBe(p.toLowerCase());
  });
});

describe('generatePassphrase – words option', () => {
  test('generates requested number of words', () => {
    for (const n of [1, 3, 6, 10]) {
      const parts = generatePassphrase({ words: n }).split('-');
      expect(parts).toHaveLength(n);
    }
  });

  test('throws on words < 1', () => {
    expect(() => generatePassphrase({ words: 0 })).toThrow(RangeError);
    expect(() => generatePassphrase({ words: -1 })).toThrow(RangeError);
  });
});

describe('generatePassphrase – separator option', () => {
  test('uses custom separator', () => {
    const p = generatePassphrase({ words: 4, separator: ' ' });
    expect(p.split(' ')).toHaveLength(4);
    expect(p).not.toContain('-');
  });

  test('empty separator joins words directly', () => {
    const p = generatePassphrase({ words: 3, separator: '' });
    expect(p).not.toContain('-');
    expect(p).not.toContain(' ');
  });
});

describe('generatePassphrase – capitalize option', () => {
  test('capitalizes first letter of each word', () => {
    const p = generatePassphrase({ words: 4, capitalize: true });
    const parts = p.split('-');
    for (const w of parts) {
      expect(w[0]).toBe(w[0]!.toUpperCase());
    }
  });
});

describe('generatePassphrase – includeNumber option', () => {
  test('appends a single digit', () => {
    const p = generatePassphrase({ words: 4, includeNumber: true });
    const parts = p.split('-');
    expect(parts).toHaveLength(5);
    expect(parts[4]).toMatch(/^\d$/);
  });
});

describe('generatePassphrase – randomness', () => {
  test('produces different passphrases across calls', () => {
    const results = new Set(Array.from({ length: 20 }, () => generatePassphrase()));
    expect(results.size).toBeGreaterThan(1);
  });
});
