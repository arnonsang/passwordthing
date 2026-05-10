/**
 * Integration test, imports from the built dist/ artifacts (not src/).
 * Verifies that all six subpath exports are bundled correctly and functional.
 * Run with: bun run tests/integration/integration.test.mjs
 */

import assert from 'node:assert/strict';

// 1. core
const { validate, generate, checkTypo } = await import('../../dist/core/index.mjs');

// validate
const validResult = validate('Hello1!World', { min: 8, requireDigits: 1, requireSymbols: 1 });
assert.equal(validResult.isValid, true, 'validate: strong password should pass');

const invalidResult = validate('abc', { min: 8 });
assert.equal(invalidResult.isValid, false, 'validate: short password should fail');
assert.ok(invalidResult.failedRules.some(r => r.rule === 'min'), 'validate: min rule in failedRules');

// generate
const pwd = generate({ length: 16, includeSymbols: true });
assert.equal(pwd.length, 16, 'generate: correct length');

const pwdUpper = generate({ length: 20, includeUppercase: true, includeLowercase: false, includeDigits: false, includeSymbols: false });
assert.ok(/^[A-Z]+$/.test(pwdUpper), 'generate: uppercase-only');

// checkTypo
const typo = checkTypo('password', 'passwrd');
assert.equal(typo.match, false, 'checkTypo: no match on different strings');
assert.ok(typo.distance > 0, 'checkTypo: positive distance');

const exact = checkTypo('hello', 'hello');
assert.equal(exact.match, true, 'checkTypo: exact match');

console.log('✓ core');

// 2. strength
const { evaluateStrength, isCommonPassword, BloomFilter } = await import('../../dist/strength/index.mjs');

const strong = evaluateStrength('Tr0ub4dor&3correctHorse');
assert.ok(strong.score >= 3, 'evaluateStrength: strong password scores high');
assert.ok(typeof strong.entropyBits === 'number', 'evaluateStrength: entropyBits is a number');
assert.ok(typeof strong.timeToCrack === 'object' && strong.timeToCrack !== null, 'evaluateStrength: timeToCrack is an object');
assert.ok(typeof strong.timeToCrack.offlineFastHashing === 'string', 'evaluateStrength: timeToCrack.offlineFastHashing is a string');
assert.ok(typeof strong.timeToCrack.onlineThrottled === 'string', 'evaluateStrength: timeToCrack.onlineThrottled is a string');

const weak = evaluateStrength('123456');
assert.ok(weak.score <= 1, 'evaluateStrength: common password scores low');

assert.equal(typeof isCommonPassword('123456'), 'boolean', 'isCommonPassword: returns boolean');
assert.equal(isCommonPassword('123456'), true, 'isCommonPassword: 123456 is common');
assert.equal(isCommonPassword('X7k#mQ9!vLpR2$wN'), false, 'isCommonPassword: random string is not common');

// BloomFilter round-trip
const bf = BloomFilter.build(['alpha', 'beta', 'gamma'], 1024, 3);
assert.ok(bf.has('alpha'), 'BloomFilter: added word found');
assert.ok(!bf.has('delta'), 'BloomFilter: absent word not found');
const b64 = bf.toBase64();
const bf2 = BloomFilter.fromBase64(b64, 1024, 3);
assert.ok(bf2.has('alpha'), 'BloomFilter: round-trip preserves membership');

console.log('✓ strength');

// 3. breach
// Only test that the function exists and returns the right shape on a mock.
// We skip live network calls in integration tests.
const breachMod = await import('../../dist/breach/index.mjs');
assert.equal(typeof breachMod.checkBreach, 'function', 'breach: checkBreach is exported');

console.log('✓ breach (export check only, no live network)');

// 4. crypto
const { createSRPRegistration, createSRPProof, pbkdf2Hash } = await import('../../dist/crypto/index.mjs');

// pbkdf2Hash
const { hash, salt } = await pbkdf2Hash('my-password');
assert.equal(typeof hash, 'string', 'pbkdf2Hash: hash is string');
assert.equal(typeof salt, 'string', 'pbkdf2Hash: salt is string');
assert.equal(hash.length, 44, 'pbkdf2Hash: hash is 44-char base64');
assert.equal(salt.length, 32, 'pbkdf2Hash: salt is 32-char hex');

// determinism
const { hash: hash2 } = await pbkdf2Hash('my-password', { salt });
assert.equal(hash, hash2, 'pbkdf2Hash: deterministic with same salt');

// SRP registration
const reg = await createSRPRegistration('alice@example.com', 'correct-horse-battery-staple');
assert.equal(typeof reg.salt, 'string', 'SRP: salt is string');
assert.equal(typeof reg.verifier, 'string', 'SRP: verifier is string');
assert.equal(reg.salt.length, 32, 'SRP: salt is 32 hex chars');
assert.equal(reg.verifier.length, 512, 'SRP: verifier is 512 hex chars');
assert.ok(/^[0-9a-f]+$/.test(reg.verifier), 'SRP: verifier is lowercase hex');

// SRP proof (with a fake server B that's non-trivial)
// We can't do a full handshake without a server, so just verify the shape
const fakeB = 'a'.repeat(512);
const proof = await createSRPProof('alice@example.com', 'correct-horse-battery-staple', reg.salt, fakeB);
assert.equal(typeof proof.A, 'string', 'SRP proof: A is string');
assert.equal(typeof proof.M1, 'string', 'SRP proof: M1 is string');
assert.equal(proof.A.length, 512, 'SRP proof: A is 512 hex chars');
assert.equal(proof.M1.length, 64, 'SRP proof: M1 is 64 hex chars');

console.log('✓ crypto');

// 5. passkey
const { isSupported, arrayBufferToBase64URL, base64URLToArrayBuffer } = await import('../../dist/passkey/index.mjs');

assert.equal(typeof isSupported, 'function', 'passkey: isSupported exported');
assert.equal(typeof isSupported(), 'boolean', 'passkey: isSupported() returns boolean');

// base64URL round-trip
const original = new Uint8Array([1, 2, 3, 255, 0, 128]);
const encoded = arrayBufferToBase64URL(original.buffer);
assert.ok(!encoded.includes('+'), 'passkey: no + in base64url');
assert.ok(!encoded.includes('/'), 'passkey: no / in base64url');
assert.ok(!encoded.includes('='), 'passkey: no padding in base64url');
const decoded = new Uint8Array(base64URLToArrayBuffer(encoded));
assert.deepEqual(decoded, original, 'passkey: base64URL round-trip');

console.log('✓ passkey');

// 6. react
// Only verify exports, hooks require a DOM/React render environment
const reactMod = await import('../../dist/react/index.mjs');
assert.equal(typeof reactMod.usePassword, 'function', 'react: usePassword exported');
assert.equal(typeof reactMod.usePasskey, 'function', 'react: usePasskey exported');

console.log('✓ react (export check only, hooks require DOM)');

// CJS smoke test
// Verify CJS exports can be required (using createRequire from ESM)
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

const coreC = require('../../dist/core/index.cjs');
assert.equal(typeof coreC.validate, 'function', 'CJS core: validate exported');
assert.equal(typeof coreC.generate, 'function', 'CJS core: generate exported');
assert.equal(typeof coreC.checkTypo, 'function', 'CJS core: checkTypo exported');

const strengthC = require('../../dist/strength/index.cjs');
assert.equal(typeof strengthC.evaluateStrength, 'function', 'CJS strength: evaluateStrength exported');

const cryptoC = require('../../dist/crypto/index.cjs');
assert.equal(typeof cryptoC.pbkdf2Hash, 'function', 'CJS crypto: pbkdf2Hash exported');
assert.equal(typeof cryptoC.createSRPRegistration, 'function', 'CJS crypto: createSRPRegistration exported');

console.log('✓ CJS require smoke test');

// Done
console.log('\n✅ All integration tests passed');
