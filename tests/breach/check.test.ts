import { describe, expect, test } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '../setup.js';
import { checkBreach } from '../../src/breach/check.js';

// SHA-1 of 'password' = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
// prefix = 5BAA6, suffix = 1E4C9B93F3F0682250B6CF8331B7EE68FD8
const PASSWORD = 'password';
const HASH_PREFIX = '5BAA6';
const HASH_SUFFIX = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';

function mockHibpHandler(prefix: string, body: string) {
  return http.get(`https://api.pwnedpasswords.com/range/${prefix}`, () => {
    return HttpResponse.text(body);
  });
}

describe('checkBreach – correct SHA-1 prefix sent', () => {
  test('uses only the 5-character prefix in the URL', async () => {
    let capturedUrl = '';
    server.use(
      http.get('https://api.pwnedpasswords.com/range/:prefix', ({ request }) => {
        capturedUrl = request.url;
        return HttpResponse.text('');
      }),
    );

    await checkBreach(PASSWORD).catch(() => {});
    expect(capturedUrl).toContain(`/range/${HASH_PREFIX}`);
    // Full hash must NOT appear in the URL
    expect(capturedUrl).not.toContain(HASH_SUFFIX);
  });
});

describe('checkBreach – suffix parsing', () => {
  test('detects pwned password when suffix is in response', async () => {
    server.use(
      mockHibpHandler(
        HASH_PREFIX,
        `${HASH_SUFFIX}:9545824\r\nABCDEF1234567890ABCDEF1234567890ABC:1`,
      ),
    );

    const result = await checkBreach(PASSWORD);
    expect(result.isPwned).toBe(true);
    expect(result.occurrences).toBe(9_545_824);
  });

  test('returns not-pwned when suffix absent', async () => {
    server.use(mockHibpHandler(HASH_PREFIX, 'ABCDEF1234567890ABCDEF1234567890ABC:1\r\nXXXXX:2'));
    const result = await checkBreach(PASSWORD);
    expect(result.isPwned).toBe(false);
    expect(result.occurrences).toBe(0);
  });

  test('returns not-pwned for empty response', async () => {
    server.use(mockHibpHandler(HASH_PREFIX, ''));
    const result = await checkBreach(PASSWORD);
    expect(result.isPwned).toBe(false);
  });
});

describe('checkBreach – Add-Padding header', () => {
  test('sends Add-Padding: true header', async () => {
    let paddingHeader: string | null = null;
    server.use(
      http.get('https://api.pwnedpasswords.com/range/:prefix', ({ request }) => {
        paddingHeader = request.headers.get('Add-Padding');
        return HttpResponse.text('');
      }),
    );

    await checkBreach('any_password');
    expect(paddingHeader).toBe('true');
  });
});

describe('checkBreach – error handling', () => {
  test('throws on non-ok HTTP status', async () => {
    server.use(
      http.get('https://api.pwnedpasswords.com/range/:prefix', () => {
        return new HttpResponse(null, { status: 503, statusText: 'Service Unavailable' });
      }),
    );
    await expect(checkBreach(PASSWORD)).rejects.toThrow('503');
  });
});
