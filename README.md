# passwordthing

[![CI](https://github.com/arnonsang/passwordthing/actions/workflows/npm-publish.yml/badge.svg)](https://github.com/arnonsang/passwordthing/actions/workflows/npm-publish.yml)
[![npm version](https://img.shields.io/npm/v/passwordthing)](https://www.npmjs.com/package/passwordthing)
[![npm downloads](https://img.shields.io/npm/dm/passwordthing)](https://www.npmjs.com/package/passwordthing)

Everything that app needs to handle passwords and authentication, without sending sensitive data anywhere it doesn't need to go. Password validation, generation, strength scoring, breach detection, PBKDF2 hashing, SRP-6a auth, and WebAuthn passkeys.

## Features

- **Validate** passwords against composable rules: length, character classes, no common passwords, no keyboard walks, no sequential or repeating characters
- **Generate** secure, memorable, or PIN-style passwords from a CSPRNG with no statistical bias
- **Detect typos** between two password strings (e.g. confirm-password mismatch hints)
- **Evaluate strength** with entropy-based scoring and human-readable time-to-crack estimates
- **Check breaches** against HaveIBeenPwned using k-anonymity: only 5 prefix characters ever leave the device
- **Block common passwords** locally with a Bloom filter: no server round-trip, no list downloads at runtime
- **Hash for your server** with PBKDF2 (SHA-256/384/512, OWASP 2024 iteration defaults) to derive and compare keys without ever logging the raw password
- **Authenticate without passwords** using SRP-6a (RFC 5054) client-side registration and login proofs
- **Go passwordless** with WebAuthn passkey helpers for registration and authentication
- **React-ready** with `usePassword` and `usePasskey` hooks that wire everything together out of the box

## Installation

```bash
npm install passwordthing
# or
bun add passwordthing
```

React is an optional peer dependency. Install it only if you use `passwordthing/react`.

## Modules

| Subpath | Contents |
|---|---|
| `passwordthing/core` | `validate`, `generate`, `checkTypo` |
| `passwordthing/strength` | `evaluateStrength`, `isCommonPassword`, `BloomFilter` |
| `passwordthing/breach` | `checkBreach` |
| `passwordthing/crypto` | `pbkdf2Hash`, `createSRPRegistration`, `createSRPProof` |
| `passwordthing/passkey` | `isSupported`, `register`, `authenticate` |
| `passwordthing/react` | `usePassword`, `usePasskey` |

---

## `passwordthing/core`

### `validate(password, options?)`

Validates a password against a set of rules. Returns a discriminated union result.

```ts
import { validate } from 'passwordthing/core';

const result = validate('Hunter2!', {
  min: 8,
  uppercase: 1,
  digits: 1,
  symbols: 1,
  spaces: false,
  noSequential: true,
  noRepeating: 3,
});

if (result.isValid) {
  // result.failedRules is []
} else {
  for (const { rule, message } of result.failedRules) {
    console.error(rule, message);
  }
}
```

**`ValidationOptions`**

| Option | Type | Description |
|---|---|---|
| `min` | `number` | Minimum character length |
| `max` | `number` | Maximum character length |
| `digits` | `number` | Minimum number of digit characters |
| `lowercase` | `number` | Minimum number of lowercase characters |
| `uppercase` | `number` | Minimum number of uppercase characters |
| `symbols` | `number` | Minimum number of symbol characters |
| `spaces` | `boolean` | Set `false` to disallow whitespace |
| `not` | `string[]` | Blocklist of exact passwords (timing-safe comparison) |
| `regex` | `RegExp` | Custom pattern the password must match |
| `noSequential` | `boolean` | Reject passwords with sequential runs (`abc`, `123`, `cba`) |
| `noRepeating` | `number` | Max consecutive identical characters allowed |
| `is` | `(val: string) => boolean \| string` | Custom validator; return `true` to pass, `false` or a message string to fail |

**`ValidationResult`**

```ts
type ValidationResult =
  | { isValid: true; failedRules: [] }
  | { isValid: false; failedRules: Array<{ rule: string; message: string }> };
```

---

### `generate(options)`

Generates a cryptographically secure random password. Uses `crypto.getRandomValues` with rejection sampling to eliminate modulo bias.

```ts
import { generate } from 'passwordthing/core';

const password = generate({
  length: 20,
  includeUppercase: true,
  includeLowercase: true,
  includeDigits: true,
  includeSymbols: true,
  excludeAmbiguous: true, // removes i, l, 1, L, o, 0, O, I
});
```

**`GeneratorOptions`**

| Option | Type | Default | Description |
|---|---|---|---|
| `length` | `number` | required | Output length |
| `includeUppercase` | `boolean` | `true` | Include A-Z |
| `includeLowercase` | `boolean` | `true` | Include a-z |
| `includeDigits` | `boolean` | `true` | Include 0-9 |
| `includeSymbols` | `boolean` | `false` | Include symbols |
| `excludeAmbiguous` | `boolean` | `false` | Remove visually similar characters |
| `pronounceable` | `boolean` | `false` | Alternate consonants and vowels |
| `customCharset` | `string` | | Override all other character options |

---

### `checkTypo(a, b)`

Computes the Levenshtein edit distance between two strings and returns a human-readable typo verdict. Useful for "confirm password" fields.

```ts
import { checkTypo } from 'passwordthing/core';

checkTypo('correct', 'corect');
// { match: false, distance: 1, message: '1 character off' }

checkTypo('password', 'password');
// { match: true, distance: 0, message: 'Match' }
```

**`TypoResult`**

```ts
interface TypoResult {
  match: boolean;
  distance: number;
  message: 'Match' | '1 character off' | 'Significantly different';
}
```

---

## `passwordthing/strength`

### `evaluateStrength(password, options?)`

Evaluates password entropy with penalization for common passwords, leet-speak substitutions, keyboard walks, and user-supplied personal inputs (name, email, etc.).

```ts
import { evaluateStrength } from 'passwordthing/strength';

const result = evaluateStrength('Tr0ub4dor&3', {
  preset: 'ADVANCED',
  userInputs: ['alice', 'alice@example.com'],
});

console.log(result.score);        // 0-4
console.log(result.label);        // 'Very Weak' | 'Weak' | 'Fair' | 'Strong' | 'Very Strong'
console.log(result.entropyBits);  // e.g. 52.41
console.log(result.timeToCrack);
// { offlineFastHashing: '3 hours', onlineThrottled: '34 years' }
console.log(result.feedback.warning);      // string | null
console.log(result.feedback.suggestions);  // string[]
```

**`EvaluateStrengthOptions`**

| Option | Type | Description |
|---|---|---|
| `preset` | `'BASIC' \| 'ADVANCED' \| 'STRICT'` | Entropy thresholds used to compute the score |
| `userInputs` | `string[]` | Personal info to penalize if found in the password |

**`StrengthResult`**

```ts
interface StrengthResult {
  score: 0 | 1 | 2 | 3 | 4;
  entropyBits: number;
  label: 'Very Weak' | 'Weak' | 'Fair' | 'Strong' | 'Very Strong';
  timeToCrack: {
    offlineFastHashing: string;  // GPU cluster cracking speed
    onlineThrottled: string;     // Rate-limited online attack speed
  };
  feedback: {
    warning: string | null;
    suggestions: string[];
  };
}
```

---

### `isCommonPassword(password)`

Checks whether a password appears in the common password list using a Bloom filter. Runs entirely in-memory with no network request.

```ts
import { isCommonPassword } from 'passwordthing/strength';

isCommonPassword('123456'); // true
isCommonPassword('xK9#mPqR!'); // false
```

Returns `boolean`. May produce false positives (by design of Bloom filters) but never false negatives.

---

### `BloomFilter`

Low-level Bloom filter class used internally. Exposed for advanced use cases.

```ts
import { BloomFilter } from 'passwordthing/strength';

const filter = BloomFilter.fromBase64(serializedData);
filter.has('somePassword');
```

---

## `passwordthing/breach`

### `checkBreach(password)`

Checks whether a password has appeared in known data breaches using the HaveIBeenPwned Passwords API. Uses k-anonymity: only the first 5 hex characters of the SHA-1 hash are sent over the network.

```ts
import { checkBreach } from 'passwordthing/breach';

const result = await checkBreach('hunter2');
// { isPwned: true, occurrences: 17984 }
```

**`BreachResult`**

```ts
interface BreachResult {
  isPwned: boolean;
  occurrences: number;
}
```

Throws if the HIBP API returns a non-2xx status.

---

## `passwordthing/crypto`

### `pbkdf2Hash(password, options?)`

Derives a server-safe key from a password using PBKDF2. Default iterations follow OWASP 2024 recommendations per algorithm. Store the returned `hash` and `salt` in your database; never store the plaintext password.

```ts
import { pbkdf2Hash } from 'passwordthing/crypto';

// Registration: generate a fresh salt (SHA-256, 600k iterations by default)
const { hash, salt } = await pbkdf2Hash('my-password');

// Login: reproduce the same hash with the stored salt
const { hash: loginHash } = await pbkdf2Hash('my-password', { salt });
const matches = loginHash === hash;

// Use SHA-512 (210k iterations by default per OWASP)
const { hash: h512, salt: s512 } = await pbkdf2Hash('my-password', { hash: 'SHA-512' });
```

**`Pbkdf2HashOptions`**

| Option | Type | Default | Description |
|---|---|---|---|
| `salt` | `string` | generated | Hex-encoded salt. Omit on registration, provide on login. |
| `hash` | `'SHA-256' \| 'SHA-384' \| 'SHA-512'` | `'SHA-256'` | PBKDF2 hash algorithm |
| `iterations` | `number` | OWASP default for chosen algorithm | Override iteration count |

OWASP 2024 default iterations by algorithm:

| Algorithm | Default iterations |
|---|---|
| `SHA-256` | 600,000 |
| `SHA-384` | 210,000 |
| `SHA-512` | 210,000 |

**`Pbkdf2HashResult`**

```ts
interface Pbkdf2HashResult {
  hash: string;  // base64-encoded derived key (256-bit)
  salt: string;  // hex-encoded salt
}
```

---

### `createSRPRegistration(identity, password)`

Computes the SRP-6a verifier (RFC 5054, 2048-bit MODP group, SHA-256). Send `salt` and `verifier` to your server for storage. The password never leaves the client.

```ts
import { createSRPRegistration } from 'passwordthing/crypto';

const { salt, verifier } = await createSRPRegistration('alice@example.com', 'correct-horse');
// Store salt and verifier on the server
```

**`SRPRegistration`**

```ts
interface SRPRegistration {
  salt: string;      // hex-encoded random salt
  verifier: string;  // hex-encoded g^x mod N
}
```

---

### `createSRPProof(identity, password, serverSalt, serverB)`

Computes the SRP-6a client proof for authentication. Send `A` and `M1` to the server for verification.

```ts
import { createSRPProof } from 'passwordthing/crypto';

const { A, M1 } = await createSRPProof(
  'alice@example.com',
  'correct-horse',
  serverSalt,  // from registration or server ephemeral response
  serverB,     // server's public ephemeral value B
);
// POST { A, M1 } to server for verification
```

**`SRPProof`**

```ts
interface SRPProof {
  A: string;   // hex-encoded client public ephemeral
  M1: string;  // hex-encoded client proof
}
```

---

## `passwordthing/passkey`

WebAuthn passkey helpers. These wrap the `navigator.credentials` API with typed inputs and base64url-encoded outputs suitable for sending to a server.

### `isSupported()`

Returns `true` if the current environment supports WebAuthn platform authenticators.

```ts
import { isSupported } from 'passwordthing/passkey';

if (!isSupported()) {
  // Fall back to password login
}
```

---

### `register(options)`

Initiates a passkey registration ceremony.

```ts
import { register } from 'passwordthing/passkey';

const response = await register({
  challenge: serverChallenge,         // base64url string from server
  rpId: 'example.com',
  rpName: 'Example App',
  userId: base64urlUserId,
  userName: 'alice',
  userDisplayName: 'Alice',
  timeout: 60000,
  attestation: 'none',
  authenticatorAttachment: 'platform',
});

// Send response to server for verification
```

**`PasskeyRegisterOptions`**

| Option | Type | Description |
|---|---|---|
| `challenge` | `string` | base64url challenge from server |
| `rpId` | `string` | Relying party domain |
| `rpName` | `string` | Relying party display name |
| `userId` | `string` | base64url user identifier |
| `userName` | `string` | Username |
| `userDisplayName` | `string` | Display name shown to user |
| `timeout` | `number` | Optional timeout in milliseconds |
| `attestation` | `AttestationConveyancePreference` | Optional attestation type |
| `authenticatorAttachment` | `AuthenticatorAttachment` | Optional `'platform'` or `'cross-platform'` |

Returns `PasskeyRegistrationResponse` (serialized credential with base64url-encoded buffers).

---

### `authenticate(options)`

Initiates a passkey authentication ceremony.

```ts
import { authenticate } from 'passwordthing/passkey';

const response = await authenticate({
  challenge: serverChallenge,
  rpId: 'example.com',
  allowCredentials: [{ id: storedCredentialId, type: 'public-key' }],
  userVerification: 'preferred',
});

// Send response to server for verification
```

**`PasskeyAuthenticateOptions`**

| Option | Type | Description |
|---|---|---|
| `challenge` | `string` | base64url challenge from server |
| `rpId` | `string` | Relying party domain |
| `timeout` | `number` | Optional timeout in milliseconds |
| `allowCredentials` | `Array<{ id: string; type: 'public-key' }>` | Credential IDs to allow |
| `userVerification` | `UserVerificationRequirement` | Optional verification requirement |

Returns `PasskeyAuthenticationResponse`.

---

## `passwordthing/react`

### `usePassword(config?)`

A React hook that combines validation, strength evaluation, breach checking, and typo detection into a single composable hook.

```tsx
import { usePassword } from 'passwordthing/react';

function PasswordField() {
  const {
    value,
    setValue,
    isValid,
    failedRules,
    strength,
    breach,
    typo,
  } = usePassword({
    rules: { min: 8, uppercase: 1, symbols: 1 },
    strengthPreset: 'ADVANCED',
    enableBreachCheck: true,
  });

  return (
    <>
      <input value={value} onChange={(e) => setValue(e.target.value)} />
      <p>Score: {strength.score} / 4 ({strength.label})</p>
      {breach.isPwned && <p>This password has been breached {breach.occurrences} times.</p>}
      {typo && <p>Typo hint: {typo.message}</p>}
    </>
  );
}
```

**`UsePasswordConfig`**

| Option | Type | Description |
|---|---|---|
| `rules` | `ValidationOptions` | Validation rules (same as `validate`) |
| `strengthPreset` | `StrengthPreset` | Preset for strength scoring |
| `enableBreachCheck` | `boolean` | Enable HIBP breach check (debounced) |

**`UsePasswordReturn`**

| Property | Type | Description |
|---|---|---|
| `value` | `string` | Current password value |
| `setValue` | `(val: string) => void` | Update the password |
| `isValid` | `boolean` | Whether all validation rules pass |
| `failedRules` | `FailedRule[]` | List of failed rules with messages |
| `strength` | `StrengthResult` | Strength evaluation result |
| `breach` | `BreachStatus` | HIBP breach check status |
| `typo` | `TypoResult \| null` | Typo hint (requires a confirm field) |

---

### `usePasskey()`

A React hook for triggering passkey register and authenticate flows with loading and error state management.

```tsx
import { usePasskey } from 'passwordthing/react';

function PasskeyButton() {
  const { isSupported, isAuthenticating, error, register, authenticate } = usePasskey();

  if (!isSupported) return <p>Passkeys not supported on this device.</p>;

  return (
    <>
      <button
        disabled={isAuthenticating}
        onClick={() => register({ challenge, rpId, rpName, userId, userName, userDisplayName })}
      >
        Register passkey
      </button>
      {error && <p>Error: {error.message}</p>}
    </>
  );
}
```

**`UsePasskeyReturn`**

| Property | Type | Description |
|---|---|---|
| `isSupported` | `boolean` | Whether WebAuthn is available |
| `isAuthenticating` | `boolean` | Whether a ceremony is in progress |
| `error` | `Error \| null` | Last error, if any |
| `register` | `(options: PasskeyRegisterOptions) => Promise<PasskeyRegistrationResponse \| null>` | Start a registration ceremony |
| `authenticate` | `(options: PasskeyAuthenticateOptions) => Promise<PasskeyAuthenticationResponse \| null>` | Start an authentication ceremony |

---

## Performance

All figures measured on Node.js v24 with `crypto.getRandomValues` and `crypto.subtle` available. Numbers represent sustained throughput on a single thread.

| Operation | Throughput | Per call | Notes |
|---|---|---|---|
| `validate()` | ~1.7M ops/sec | ~0.58µs | Single-pass char analysis, O(1) symbol lookup via typed array |
| `generate()` | ~450K ops/sec | ~2.2µs | CSPRNG-backed; uses a pre-filled `Uint32Array` buffer to amortize `getRandomValues` calls |
| `evaluateStrength()` | ~217K ops/sec | ~4.6µs | Pre-computed keyboard n-gram `Set`, single-pass entropy calc |
| `pbkdf2Hash()` | ~8 ops/sec | ~129ms | Intentionally slow by design; 600K iterations (OWASP 2024 for SHA-256) |

**`validate()`** runs a single character loop to collect uppercase, lowercase, digit, and symbol counts alongside sequential and repeating pattern checks. No regex, no multiple passes.

**`generate()`** fills a `Uint32Array(256)` buffer with one `getRandomValues` call and drains it across multiple `generate()` invocations, reducing CSPRNG overhead by ~30x. Charset lookup is O(1) via a precomputed array indexed by a 5-bit bitmask.

**`evaluateStrength()`** pre-computes all keyboard row n-grams (2-4 chars) into a `Set` at module load. Per-call cost is O(n) string slices with O(1) `Set.has` lookups rather than scanning each keyboard row on every call.

**`pbkdf2Hash()`** throughput scales with iteration count. At `iterations: 1000` (testing only) throughput is ~1,700 ops/sec; production defaults are deliberately expensive to resist brute-force attacks.

## Building

```bash
bun run build          # compile all subpath entries to dist/
bun run build:bloom    # fetch SecLists and embed Bloom filter data
bun run typecheck      # tsc --noEmit
```

## Testing

```bash
bun run test               # unit tests (Vitest, 128 tests)
bun run test:integration   # integration tests against built dist/
bun run test:coverage      # coverage report
```

## Requirements

- Node.js 20 or later (or any modern runtime with `crypto.subtle` and `crypto.getRandomValues`)
- React 19 (optional, only needed for `passwordthing/react`)

## License

MIT
