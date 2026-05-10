export interface BreachResult {
  isPwned: boolean;
  occurrences: number;
}

const HIBP_URL = 'https://api.pwnedpasswords.com/range/';

async function sha1Hex(input: string): Promise<string> {
  const encoded = new TextEncoder().encode(input);
  const buffer = await globalThis.crypto.subtle.digest('SHA-1', encoded);
  const bytes = new Uint8Array(buffer);
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

function parseHibpResponse(body: string, suffix: string): number {
  const lines = body.split('\n');
  for (const line of lines) {
    const sep = line.indexOf(':');
    if (sep === -1) continue;
    const lineSuffix = line.slice(0, sep).trim().toUpperCase();
    if (lineSuffix === suffix) {
      return parseInt(line.slice(sep + 1).trim(), 10);
    }
  }
  return 0;
}

export async function checkBreach(password: string): Promise<BreachResult> {
  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const response = await fetch(`${HIBP_URL}${prefix}`, {
    headers: { 'Add-Padding': 'true' },
  });

  if (!response.ok) {
    throw new Error(`HIBP API error: ${response.status} ${response.statusText}`);
  }

  const body = await response.text();
  const occurrences = parseHibpResponse(body, suffix);

  return { isPwned: occurrences > 0, occurrences };
}
