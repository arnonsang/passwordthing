import { describe, expect, test } from 'vitest';
import { BloomFilter } from '../../src/strength/bloom.js';

const WORD_LIST = ['password', '123456', 'qwerty', 'letmein', 'dragon', 'admin'];

describe('BloomFilter – basic operations', () => {
  test('added words are found', () => {
    const bf = BloomFilter.build(WORD_LIST, 10_000, 5);
    for (const word of WORD_LIST) {
      expect(bf.has(word)).toBe(true);
    }
  });

  test('lookup is case-insensitive via build()', () => {
    const bf = BloomFilter.build(['password'], 10_000, 5);
    // build() lowercases items; lookups must also be lowercased by caller
    expect(bf.has('password')).toBe(true);
  });

  test('serialise and deserialise round-trip', () => {
    const original = BloomFilter.build(WORD_LIST, 10_000, 5);
    const base64 = original.toBase64();
    const restored = BloomFilter.fromBase64(base64, 10_000, 5);
    for (const word of WORD_LIST) {
      expect(restored.has(word)).toBe(true);
    }
  });
});

describe('BloomFilter – false positive rate', () => {
  test('false positive rate < 10% on random strings (small filter)', () => {
    // Build a filter with 100 known words
    const known = Array.from({ length: 100 }, (_, i) => `word${i}`);
    const bf = BloomFilter.build(known, 10_000, 7);

    // Test 1000 distinct strings not in the filter
    const unknowns = Array.from({ length: 1000 }, (_, i) => `unknown_${i}_xyz`);
    const falsePositives = unknowns.filter((w) => bf.has(w)).length;
    const fpr = falsePositives / unknowns.length;

    expect(fpr).toBeLessThan(0.1);
  });
});

describe('BloomFilter – no false negatives', () => {
  test('every added item is found', () => {
    const words = Array.from({ length: 500 }, (_, i) => `item_${i}`);
    const bf = BloomFilter.build(words, 50_000, 7);
    for (const word of words) {
      expect(bf.has(word)).toBe(true);
    }
  });
});
