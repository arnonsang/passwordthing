/**
 * @module strength/bloom
 *
 * Bloom filter using FNV-1a hashing with Kirsch-Mitzenmacher
 * double-hashing. Supports serialization to/from base64 and
 * bulk construction from word lists. Used internally for
 * constant-time common-password lookups.
 */

import { BLOOM_BIT_SIZE, BLOOM_HASH_COUNT, BLOOM_DATA, FALLBACK_LIST } from './common-passwords.js';

export class BloomFilter {
  private readonly bits: Uint8Array;

  /**
   * @param bitCount - Total number of bits in the filter.
   * @param hashCount - Number of hash functions (iterations).
   * @param data - Pre-initialized bit array, or undefined for empty.
   */
  constructor(
    private readonly bitCount: number,
    private readonly hashCount: number,
    data?: Uint8Array,
  ) {
    this.bits = data ?? new Uint8Array(Math.ceil(bitCount / 8));
  }

  // FNV-1a 32-bit hash (seed variant via XOR with seed before main loop)
  private fnv1a(str: string, seed: number): number {
    let h = (0x811c9dc5 ^ seed) >>> 0;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h % this.bitCount;
  }

  // Double hashing: h_i(x) = (h1(x) + i * h2(x)) mod m
  private position(i: number, h1: number, h2: number): number {
    return (h1 + i * h2) % this.bitCount;
  }

  /** Insert an item into the filter. */
  add(item: string): void {
    const h1 = this.fnv1a(item, 0x00000000);
    const h2 = this.fnv1a(item, 0xdeadbeef);
    for (let i = 0; i < this.hashCount; i++) {
      const pos = this.position(i, h1, h2);
      this.bits[Math.floor(pos / 8)]! |= 1 << pos % 8;
    }
  }

  /** Test whether an item might be in the filter (may return false positives, never false negatives). */
  has(item: string): boolean {
    const h1 = this.fnv1a(item, 0x00000000);
    const h2 = this.fnv1a(item, 0xdeadbeef);
    for (let i = 0; i < this.hashCount; i++) {
      const pos = this.position(i, h1, h2);
      if (!(this.bits[Math.floor(pos / 8)]! & (1 << pos % 8))) return false;
    }
    return true;
  }

  /** Serialize the filter bit array to a base64 string. */
  toBase64(): string {
    return btoa(String.fromCharCode(...this.bits));
  }

  /** Deserialize a base64-encoded bit array into a BloomFilter. */
  static fromBase64(data: string, bitCount: number, hashCount: number): BloomFilter {
    const binary = atob(data);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new BloomFilter(bitCount, hashCount, bytes);
  }

  /** Build a BloomFilter from a list of words. */
  static build(words: readonly string[], bitCount: number, hashCount: number): BloomFilter {
    const filter = new BloomFilter(bitCount, hashCount);
    for (const word of words) filter.add(word.toLowerCase());
    return filter;
  }
}

let _filter: BloomFilter | null = null;

function getFilter(): BloomFilter {
  if (_filter !== null) return _filter;
  _filter =
    BLOOM_DATA !== ''
      ? BloomFilter.fromBase64(BLOOM_DATA, BLOOM_BIT_SIZE, BLOOM_HASH_COUNT)
      : BloomFilter.build(FALLBACK_LIST, BLOOM_BIT_SIZE, BLOOM_HASH_COUNT);
  return _filter;
}

/**
 * Check whether a password appears in the common password dictionary.
 *
 * Uses a lazy-initialized singleton BloomFilter backed by ~96 Kbit
 * of pre-computed data covering 99,999 common passwords.
 *
 * @param password - The password to check (compared lowercase).
 * @returns `true` if the password is likely common.
 */
export function isCommonPassword(password: string): boolean {
  return getFilter().has(password.toLowerCase());
}
