import { describe, expect, test, vi, afterEach } from 'vitest';
import { generateSecret, generateTOTP, verifyTOTP, generateOTPAuthURL } from '../../src/otp/totp.js';
import { base32Encode } from '../../src/otp/base32.js';

// RFC 6238 test secret
const RFC_SECRET_BYTES = new TextEncoder().encode('12345678901234567890');
const RFC_SECRET = base32Encode(RFC_SECRET_BYTES);

afterEach(() => {
  vi.useRealTimers();
});

describe('generateSecret', () => {
  test('returns a 32-char base32 string (20 bytes)', () => {
    const secret = generateSecret();
    expect(typeof secret).toBe('string');
    expect(secret).toHaveLength(32);
    expect(/^[A-Z2-7]+$/.test(secret)).toBe(true);
  });

  test('generates unique values', () => {
    expect(generateSecret()).not.toBe(generateSecret());
  });
});

describe('generateTOTP', () => {
  // RFC 6238 vector: T=59 → counter=1 (period=30), expected TOTP for SHA-1 = "94287082"
  test('RFC 6238 SHA-1 vector at T=59', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(59_000);
    const code = await generateTOTP(RFC_SECRET, { digits: 8 });
    expect(code).toBe('94287082');
  });

  test('returns 6-digit string by default', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(Date.now());
    const code = await generateTOTP(RFC_SECRET);
    expect(code).toHaveLength(6);
    expect(/^\d+$/.test(code)).toBe(true);
  });
});

describe('verifyTOTP', () => {
  test('verifies current TOTP', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(59_000);
    const code = await generateTOTP(RFC_SECRET);
    expect(await verifyTOTP(RFC_SECRET, code)).toBe(true);
  });

  test('rejects wrong token', async () => {
    expect(await verifyTOTP(RFC_SECRET, '000000')).toBe(false);
  });

  test('accepts token within drift window', async () => {
    vi.useFakeTimers();
    const now = 60_000; // second period boundary
    vi.setSystemTime(now);
    // Generate code for previous window
    vi.setSystemTime(now - 30_000);
    const prevCode = await generateTOTP(RFC_SECRET);
    // Verify from current time — should pass within ±1
    vi.setSystemTime(now);
    expect(await verifyTOTP(RFC_SECRET, prevCode)).toBe(true);
  });
});

describe('generateOTPAuthURL', () => {
  test('produces valid otpauth URL', () => {
    const url = generateOTPAuthURL({
      secret: 'JBSWY3DPEHPK3PXP',
      issuer: 'Example',
      account: 'user@example.com',
    });
    expect(url).toMatch(/^otpauth:\/\/totp\//);
    expect(url).toContain('secret=JBSWY3DPEHPK3PXP');
    expect(url).toContain('issuer=Example');
    expect(url).toContain('algorithm=SHA1');
    expect(url).toContain('digits=6');
    expect(url).toContain('period=30');
  });

  test('respects custom options', () => {
    const url = generateOTPAuthURL({
      secret: 'JBSWY3DPEHPK3PXP',
      issuer: 'Acme',
      account: 'alice',
      algorithm: 'SHA-256',
      digits: 8,
      period: 60,
    });
    expect(url).toContain('algorithm=SHA256');
    expect(url).toContain('digits=8');
    expect(url).toContain('period=60');
  });
});
