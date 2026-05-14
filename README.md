# passwordthing

[![CI](https://github.com/arnonsang/passwordthing/actions/workflows/npm-publish.yml/badge.svg)](https://github.com/arnonsang/passwordthing/actions/workflows/npm-publish.yml)
[![npm version](https://img.shields.io/npm/v/passwordthing)](https://www.npmjs.com/package/passwordthing)
[![npm downloads](https://img.shields.io/npm/dm/passwordthing)](https://www.npmjs.com/package/passwordthing)

Everything that app needs to handle passwords and authentication, without sending sensitive data anywhere it doesn't need to go. Password validation, generation, strength scoring, breach detection, PBKDF2 hashing, SRP-6a auth, WebAuthn passkeys, TOTP/HOTP, and OAuth 2.0 PKCE.

## Features

- **Validate** passwords against composable rules: length, character classes, no common passwords, no keyboard walks, no sequential or repeating characters
- **Generate** secure, memorable, or PIN-style passwords from a CSPRNG with no statistical bias
- **Generate passphrases** with a diceware-style word list (1191 words, ~10.2 bits/word) — no dependencies, CSPRNG-backed
- **Generate in batches** with `generateBatch` for producing multiple passwords in one call
- **Detect typos** between two password strings (e.g. confirm-password mismatch hints)
- **Evaluate strength** with entropy-based scoring, human-readable time-to-crack estimates, and penalties for common passwords, leet-speak, keyboard walks (horizontal and vertical), date patterns, and character repetition
- **Check breaches** against HaveIBeenPwned using k-anonymity: only 5 prefix characters ever leave the device, with configurable timeout and optional sessionStorage caching
- **Block common passwords** locally with a Bloom filter covering 99,999 passwords at ~1% false-positive rate: no server round-trip, no list downloads at runtime
- **Encrypt vault data** client-side with AES-256-GCM and PBKDF2 key derivation (OWASP 2024 defaults)
- **Hash for your server** with PBKDF2 (SHA-256/384/512, OWASP 2024 iteration defaults) to derive and compare keys without ever logging the raw password
- **Authenticate without passwords** using SRP-6a (RFC 5054) client-side registration and login proofs
- **Go passwordless** with WebAuthn passkey helpers for registration and authentication, including server-options API for direct integration with any WebAuthn server
- **Generate and verify TOTP/HOTP** codes (RFC 6238 / RFC 4226) using WebCrypto with zero dependencies
- **PKCE helpers** for OAuth 2.0 flows (RFC 7636): generate a code verifier and S256 challenge
- **Framework-ready** with `usePassword` and `usePasskey` hooks for React, Vue 3, and Svelte 5

## Installation

```bash
npm install passwordthing
# or
bun add passwordthing
```

React, Vue, and Svelte are optional peer dependencies. Install only what you use.

## Modules

| Subpath | Contents |
|---|---|
| [`passwordthing/core`](#passwordthingcore) | `validate`, `generate`, `generateBatch`, `generatePassphrase`, `checkTypo` |
| [`passwordthing/strength`](#passwordthingstrength) | `evaluateStrength`, `isCommonPassword`, `BloomFilter` |
| [`passwordthing/breach`](#passwordthingbreach) | `checkBreach` |
| [`passwordthing/crypto`](#passwordthingcrypto) | `pbkdf2Hash`, `encrypt`, `decrypt`, `createSRPRegistration`, `createSRPProof` |
| [`passwordthing/passkey`](#passwordthingpasskey) | `isSupported`, `register`, `authenticate`, `registerWithServerOptions`, `authenticateWithServerOptions` |
| [`passwordthing/otp`](#passwordthingotp) | `generateSecret`, `generateTOTP`, `verifyTOTP`, `generateOTPAuthURL`, `hotp` |
| [`passwordthing/pkce`](#passwordthingpkce) | `generateCodeVerifier`, `generateCodeChallenge` |
| [`passwordthing/react`](#passwordthingreact) | `usePassword`, `usePasskey` |
| [`passwordthing/vue`](#passwordthingvue) | `usePassword`, `usePasskey` |
| [`passwordthing/svelte`](#passwordthingsvelte) | `usePassword`, `usePasskey` |

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

### `generateBatch(count, options)`

Generates multiple passwords in a single call. Equivalent to calling `generate(options)` `count` times.

```ts
import { generateBatch } from 'passwordthing/core';

const suggestions = generateBatch(5, {
  length: 16,
  includeSymbols: true,
  excludeAmbiguous: true,
});
// ['Kx9#mPqR!vZnTy2', ...]
```

Throws `RangeError` if `count < 1`.

---

### `generatePassphrase(options?)`

Generates a cryptographically secure diceware-style passphrase. Uses a built-in 1191-word list (~10.2 bits/word). Four words yields ~41 bits of entropy; six words yields ~61 bits.

```ts
import { generatePassphrase } from 'passwordthing/core';

generatePassphrase();
// 'coral-brave-stomp-lofty'

generatePassphrase({ words: 6, capitalize: true, includeNumber: true });
// 'Coral-Brave-Stomp-Lofty-Suite-Epoch-7'
```

**`PassphraseOptions`**

| Option | Type | Default | Description |
|---|---|---|---|
| `words` | `number` | `4` | Number of words. Minimum `1`. |
| `separator` | `string` | `'-'` | Word separator |
| `capitalize` | `boolean` | `false` | Capitalize first letter of each word |
| `includeNumber` | `boolean` | `false` | Append one random digit (0-9) |

Throws `RangeError` if `words < 1`.

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

Evaluates password entropy with penalties for: common passwords (Bloom filter, 99,999-word list), leet-speak substitutions, keyboard walks (horizontal rows and vertical columns), date and year patterns, character repetition dominance, and user-supplied personal inputs (name, email, etc.).

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

### `checkBreach(password, options?)`

Checks whether a password has appeared in known data breaches using the HaveIBeenPwned Passwords API. Uses k-anonymity: only the first 5 hex characters of the SHA-1 hash are sent over the network. Includes `Add-Padding: true` for traffic-analysis resistance.

```ts
import { checkBreach } from 'passwordthing/breach';

const result = await checkBreach('hunter2');
// { isPwned: true, occurrences: 17984 }

// With timeout and session caching (avoids refetch for same prefix)
const result2 = await checkBreach('mypassword', {
  timeoutMs: 3000,
  cache: 'session',
});
```

**`BreachCheckOptions`**

| Option | Type | Default | Description |
|---|---|---|---|
| `timeoutMs` | `number` | `5000` | Request timeout in milliseconds. Set to `0` to disable. |
| `signal` | `AbortSignal` | | External abort signal to cancel the request |
| `cache` | `'session' \| 'none'` | `'none'` | Cache prefix responses in `sessionStorage` to avoid redundant fetches for passwords sharing the same 5-char SHA-1 prefix. SSR-safe. |

**`BreachResult`**

```ts
interface BreachResult {
  isPwned: boolean;
  occurrences: number;
}
```

Throws `Error` if the HIBP API returns a non-2xx status. Throws `DOMException` if the request times out or is aborted.

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

### `encrypt(plaintext, password, options?)` / `decrypt(data, password, options?)`

AES-256-GCM authenticated encryption with PBKDF2 key derivation. Suitable for client-side vault storage (e.g. encrypting a JSON blob of saved passwords with a master password). Each `encrypt` call generates a fresh random salt and IV, so identical inputs produce different ciphertext.

```ts
import { encrypt, decrypt } from 'passwordthing/crypto';

// Encrypt
const vault = await encrypt(JSON.stringify(myPasswords), masterPassword);
localStorage.setItem('vault', JSON.stringify(vault));

// Decrypt
const stored = JSON.parse(localStorage.getItem('vault')!);
const plain = await decrypt(stored, masterPassword);
```

**`EncryptOptions`**

| Option | Type | Default | Description |
|---|---|---|---|
| `hash` | `'SHA-256' \| 'SHA-384' \| 'SHA-512'` | `'SHA-256'` | PBKDF2 hash algorithm |
| `iterations` | `number` | OWASP default for chosen algorithm | Override PBKDF2 iteration count |

**`EncryptedData`**

```ts
interface EncryptedData {
  ciphertext: string;  // base64-encoded AES-GCM ciphertext (includes authentication tag)
  iv: string;          // hex-encoded 12-byte AES-GCM IV
  salt: string;        // hex-encoded 16-byte PBKDF2 salt
}
```

`decrypt` throws `DOMException` if the password is wrong or the data has been tampered with (authentication tag mismatch).

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

### `registerWithServerOptions(options)`

Accepts the `publicKey` object directly from a WebAuthn server response instead of requiring field-by-field extraction. Compatible with webauthn-rs, SimpleWebAuthn, and any spec-compliant server.

```ts
import { registerWithServerOptions } from 'passwordthing/passkey';

// server returns { publicKey: { challenge, rp, user, pubKeyCredParams, ... } }
const response = await registerWithServerOptions(serverResponse.publicKey);

// Send response to server for verification
```

**`ServerRegistrationOptions`**

| Option | Type | Description |
|---|---|---|
| `challenge` | `string` | base64url challenge from server |
| `rp` | `{ id?: string; name: string }` | Relying party info |
| `user` | `{ id: string; name: string; displayName: string }` | User info (id is base64url) |
| `pubKeyCredParams` | `Array<{ type: 'public-key'; alg: number }>` | Supported algorithms |
| `timeout` | `number` | Optional timeout in milliseconds |
| `attestation` | `AttestationConveyancePreference` | Optional attestation type |
| `authenticatorSelection` | `AuthenticatorSelectionCriteria` | Optional authenticator selection |
| `excludeCredentials` | `ServerCredentialDescriptor[]` | Optional credentials to exclude |

Returns `PasskeyRegistrationResponse`.

---

### `authenticateWithServerOptions(options)`

Accepts the `publicKey` object directly from a WebAuthn server authentication response.

```ts
import { authenticateWithServerOptions } from 'passwordthing/passkey';

const response = await authenticateWithServerOptions(serverResponse.publicKey);

// Send response to server for verification
```

**`ServerAuthenticationOptions`**

| Option | Type | Description |
|---|---|---|
| `challenge` | `string` | base64url challenge from server |
| `rpId` | `string` | Optional relying party domain |
| `timeout` | `number` | Optional timeout in milliseconds |
| `userVerification` | `UserVerificationRequirement` | Optional verification requirement |
| `allowCredentials` | `ServerCredentialDescriptor[]` | Optional credential allowlist |

Returns `PasskeyAuthenticationResponse`.

---

## `passwordthing/otp`

TOTP and HOTP implementation using WebCrypto. Zero dependencies, works in browsers and Node.js. Follows RFC 6238 (TOTP) and RFC 4226 (HOTP).

### `generateSecret()`

Generates a cryptographically random 20-byte base32-encoded secret suitable for use with any TOTP authenticator app.

```ts
import { generateSecret } from 'passwordthing/otp';

const secret = generateSecret(); // e.g. 'JBSWY3DPEHPK3PXP...'
```

---

### `generateTOTP(secret, options?)`

Generates the current TOTP code for a given secret.

```ts
import { generateTOTP } from 'passwordthing/otp';

const code = await generateTOTP(secret);          // '123456'
const code8 = await generateTOTP(secret, { digits: 8 }); // '12345678'
```

**`TOTPOptions`**

| Option | Type | Default | Description |
|---|---|---|---|
| `digits` | `6 \| 8` | `6` | Output length |
| `period` | `number` | `30` | Time step in seconds |
| `algorithm` | `'SHA-1' \| 'SHA-256' \| 'SHA-512'` | `'SHA-1'` | HMAC algorithm (SHA-1 is the RFC standard) |
| `window` | `number` | `1` | Drift tolerance in periods used by `verifyTOTP` |

---

### `verifyTOTP(secret, token, options?)`

Verifies a TOTP code with configurable drift window to account for clock skew.

```ts
import { verifyTOTP } from 'passwordthing/otp';

const valid = await verifyTOTP(secret, userInput); // boolean
```

---

### `generateOTPAuthURL(options)`

Generates an `otpauth://` URL for QR code display in authenticator apps (Google Authenticator, Authy, etc.).

```ts
import { generateSecret, generateOTPAuthURL } from 'passwordthing/otp';

const secret = generateSecret();
const url = generateOTPAuthURL({
  secret,
  issuer: 'Example App',
  account: 'alice@example.com',
});
// otpauth://totp/Example%20App:alice%40example.com?secret=...&issuer=Example+App&algorithm=SHA1&digits=6&period=30
```

---

### `hotp(secret, counter, digits?, algorithm?)`

Low-level HMAC-based OTP (RFC 4226). Use `generateTOTP` / `verifyTOTP` for time-based codes.

```ts
import { hotp } from 'passwordthing/otp';

const code = await hotp(secret, counter); // '755224'
```

---

## `passwordthing/pkce`

OAuth 2.0 PKCE helpers (RFC 7636). Use with any OAuth / OIDC authorization server that supports PKCE.

### `generateCodeVerifier(length?)`

Generates a cryptographically random code verifier (43-128 characters, base64url alphabet).

```ts
import { generateCodeVerifier } from 'passwordthing/pkce';

const verifier = generateCodeVerifier(); // 64-char base64url string by default
```

| Option | Type | Default | Description |
|---|---|---|---|
| `length` | `number` | `64` | Output length between 43 and 128 |

---

### `generateCodeChallenge(verifier)`

Derives the S256 code challenge from a verifier. Send this to the authorization server; keep the verifier for the token exchange.

```ts
import { generateCodeVerifier, generateCodeChallenge } from 'passwordthing/pkce';

const verifier  = generateCodeVerifier();
const challenge = await generateCodeChallenge(verifier);

// Authorization request: include code_challenge=challenge&code_challenge_method=S256
// Token request: include code_verifier=verifier
```

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
| `registerWithServerOptions` | `(options: ServerRegistrationOptions) => Promise<PasskeyRegistrationResponse \| null>` | Register using server response directly |
| `authenticateWithServerOptions` | `(options: ServerAuthenticationOptions) => Promise<PasskeyAuthenticationResponse \| null>` | Authenticate using server response directly |

---

## `passwordthing/vue`

Vue 3 composables with the same interface contract as the React hooks. Reactive values are exposed as `Ref` / `ComputedRef` from `vue`.

```ts
import { usePassword, usePasskey } from 'passwordthing/vue';
```

`usePassword(config?)` returns reactive `value`, `isValid`, `failedRules`, `strength`, `breachStatus`, `setValue`, and `generateNew`.

`usePasskey()` returns `isSupported`, reactive `isAuthenticating` and `error` refs, plus `register`, `authenticate`, `registerWithServerOptions`, and `authenticateWithServerOptions`.

---

## `passwordthing/svelte`

Svelte composables using Svelte stores (`Writable` / `Readable` from `svelte/store`). Compatible with Svelte 4 and Svelte 5.

```ts
import { usePassword, usePasskey } from 'passwordthing/svelte';
```

`usePassword(config?)` returns a `value` writable store, `isValid`, `failedRules`, `strength`, and `breachStatus` readable stores, plus `setValue`, `generateNew`, and a `destroy` cleanup function.

`usePasskey()` returns `isSupported`, readable `isAuthenticating` and `error` stores, plus `register`, `authenticate`, `registerWithServerOptions`, and `authenticateWithServerOptions`.

---

## Performance

All figures measured on Node.js v24 with `crypto.getRandomValues` and `crypto.subtle` available. Numbers represent sustained throughput on a single thread.

| Operation | Throughput | Per call | Notes |
|---|---|---|---|
| `validate()` | ~1.9M ops/sec | ~0.53µs | Single-pass with rolling char codes, O(1) symbol lookup via typed array |
| `generate()` | ~350K ops/sec | ~2.9µs | Pre-computed charset bytes + reused output buffer; CSPRNG overhead amortized ~30x |
| `generateBatch(5)` | ~72K ops/sec | ~14µs | 5 passwords per call |
| `generateBatch(10)` | ~31K ops/sec | ~32µs | 10 passwords per call; scales linearly |
| `generatePassphrase()` | ~440K ops/sec | ~2.3µs | 4-word default; CSPRNG rejection sampling against 1191-word list |
| `evaluateStrength()` | ~52K ops/sec | ~19µs | Pre-computed keyboard n-gram `Set`; date regex, repetition scan added |
| `pbkdf2Hash()` | ~5 ops/sec | ~200ms | Intentionally slow; 600K iterations (OWASP 2024 for SHA-256) |
| `encrypt()` | ~5 ops/sec | ~200ms | Dominated by PBKDF2 key derivation |
| `decrypt()` | ~5 ops/sec | ~200ms | Dominated by PBKDF2 key derivation |
| `generateTOTP()` | ~2.3K ops/sec | ~440µs | WebCrypto HMAC-SHA1 per call |
| `verifyTOTP()` | ~940 ops/sec | ~1ms | 3 HMAC calls for ±1 window drift check |
| `generateCodeVerifier()` | ~79K ops/sec | ~13µs | CSPRNG only, no hashing |
| `generateCodeChallenge()` | ~2.5K ops/sec | ~400µs | WebCrypto SHA-256 per call |

Run benchmarks yourself with:

```bash
bun run build && node scripts/bench.mjs
```

**`validate()`** runs a single character loop with rolling `prevCode`/`prevPrevCode` variables to classify each character and detect sequential/repeating patterns without re-indexing the string. Options are destructured once at the top so V8 register-allocates them. No regex, no multiple passes.

**`generate()`** fills a `Uint32Array(256)` buffer with one `getRandomValues` call and drains it across multiple `generate()` invocations, reducing CSPRNG overhead by ~30x. The charset is pre-computed as a `Uint8Array` (avoiding `charCodeAt` per character), a module-level 256-byte output buffer is reused across calls (no heap allocation), and `TextDecoder.decode()` converts bytes to string via a native C++ path instead of `String.fromCharCode` spread.

**`generatePassphrase()`** uses the same CSPRNG buffer as `generate()` (shared `_rng` module, fills a `Uint32Array(256)` in one `getRandomValues` call and drains across invocations). Rejection sampling eliminates modulo bias with negligible overhead at 1191 words.

**`evaluateStrength()`** pre-computes all keyboard row n-grams (length 4+) and vertical column walks (exact 3-char strings) into a module-level `Set`. Per-call cost is one O(n) pass for entropy, one O(n) pass for repetition frequency, plus O(n) string-slice / `Set.has` lookups for keyboard detection. Date pattern checks use pre-compiled regexes at module scope (no recompilation per call).

**`pbkdf2Hash()` / `encrypt()` / `decrypt()`** throughput is dominated by PBKDF2 key derivation. At `iterations: 1000` (testing only) throughput is ~1,700 ops/sec; production defaults are deliberately expensive to resist brute-force attacks. `encrypt` and `decrypt` have near-identical cost since both derive the key via PBKDF2 before the AES-GCM operation.

**`generateTOTP()` / `verifyTOTP()`** cost is dominated by a single WebCrypto `HMAC.sign` call per counter step. `verifyTOTP` makes 3 calls to cover the ±1 window, so throughput is roughly 3x lower.

**`generateCodeChallenge()`** makes one `SHA-256.digest` call via WebCrypto. `generateCodeVerifier` is synchronous CSPRNG only and is ~13x faster.

## Building

```bash
bun run build          # compile all subpath entries to dist/
bun run build:bloom    # fetch SecLists and embed Bloom filter data
bun run typecheck      # tsc --noEmit
```

## Testing

```bash
bun run test               # unit tests (Vitest, 205 tests)
bun run test:integration   # integration tests against built dist/
bun run test:coverage      # coverage report
```

## Requirements

- Node.js 20 or later (or any modern runtime with `crypto.subtle` and `crypto.getRandomValues`)
- React 19 (optional, only needed for `passwordthing/react`)
- Vue 3 (optional, only needed for `passwordthing/vue`)
- Svelte 5 (optional, only needed for `passwordthing/svelte`)

## License

MIT
