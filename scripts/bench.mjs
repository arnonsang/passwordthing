/**
 * Performance benchmark: passwordthing vs well-known alternatives
 *
 * Categories:
 *   1. Password validation      - passwordthing/core vs password-validator
 *   2. Strength evaluation      - passwordthing/strength vs zxcvbn
 *   3. Password generation      - passwordthing/core vs generate-password
 *   4. Server-safe hashing      - passwordthing/crypto (PBKDF2) vs bcryptjs
 */

import { performance } from 'node:perf_hooks';

// passwordthing (built dist)
import { validate, generate } from '../dist/core/index.mjs';
import { evaluateStrength } from '../dist/strength/index.mjs';
import { pbkdf2Hash } from '../dist/crypto/index.mjs';

// competitors
import zxcvbn from 'zxcvbn';
import PasswordValidator from 'password-validator';
import * as generatePassword from 'generate-password';
import bcrypt from 'bcryptjs';

// Helpers
const PASSWORDS = [
  'password',
  'hunter2',
  'Tr0ub4dor&3',
  'correct-horse-battery-staple',
  'X!9kPq#mL2$nR7vZ',
  '123456789',
  'MyS3cur3P@ssw0rd!',
  'aaaaaaaaaaaaaaa',
  'qwertyuiop',
  '!@#$%^&*()',
];

function bench(label, fn, iterations) {
  const start = performance.now();
  for (let i = 0; i < iterations; i++) fn(i);
  const elapsed = performance.now() - start;
  return { label, iterations, elapsed, opsPerSec: Math.round(iterations / (elapsed / 1000)) };
}

async function benchAsync(label, fn, iterations) {
  const start = performance.now();
  for (let i = 0; i < iterations; i++) await fn(i);
  const elapsed = performance.now() - start;
  return { label, iterations, elapsed, opsPerSec: Math.round(iterations / (elapsed / 1000)) };
}

function printTable(title, rows) {
  console.log(`\n## ${title}\n`);
  const colWidths = [36, 10, 12, 14];
  const header = ['Library', 'Iterations', 'Time (ms)', 'ops/sec'];
  const sep = colWidths.map((w) => '-'.repeat(w)).join('-+-');
  const fmt = (cells) =>
    cells.map((c, i) => String(c).padEnd(colWidths[i])).join(' | ');
  console.log(fmt(header));
  console.log(sep);
  for (const r of rows) {
    console.log(fmt([r.label, r.iterations, r.elapsed.toFixed(1), r.opsPerSec.toLocaleString()]));
  }
  // winner
  const sorted = [...rows].sort((a, b) => b.opsPerSec - a.opsPerSec);
  const ratio = (sorted[0].opsPerSec / sorted[1].opsPerSec).toFixed(2);
  console.log(`\nFastest: ${sorted[0].label} (${ratio}x faster than ${sorted[1].label})`);
}


// 1. Validation
function benchValidation() {
  const ITERS = 50_000;

  // passwordthing
  const pwResult = bench(
    'passwordthing validate()',
    (i) => validate(PASSWORDS[i % PASSWORDS.length], {
      min: 8, uppercase: 1, digits: 1, symbols: 1, noSequential: true, noRepeating: 3,
    }),
    ITERS,
  );

  // password-validator
  const schema = new PasswordValidator();
  schema.is().min(8).has().uppercase().has().digits().has().symbols();

  const pvResult = bench(
    'password-validator',
    (i) => schema.validate(PASSWORDS[i % PASSWORDS.length]),
    ITERS,
  );

  printTable('1. Password Validation (50,000 ops each)', [pwResult, pvResult]);
}


// 2. Strength Evaluation
function benchStrength() {
  const ITERS = 10_000;

  const ptResult = bench(
    'passwordthing evaluateStrength()',
    (i) => evaluateStrength(PASSWORDS[i % PASSWORDS.length]),
    ITERS,
  );

  const zxResult = bench(
    'zxcvbn',
    (i) => zxcvbn(PASSWORDS[i % PASSWORDS.length]),
    ITERS,
  );

  printTable('2. Strength Evaluation (10,000 ops each)', [ptResult, zxResult]);
}


// 3. Password Generation
function benchGenerate() {
  const ITERS = 10_000;

  const ptResult = bench(
    'passwordthing generate()',
    () => generate({ length: 20, includeUppercase: true, includeLowercase: true, includeDigits: true, includeSymbols: true }),
    ITERS,
  );

  const gpResult = bench(
    'generate-password',
    () => generatePassword.generate({ length: 20, numbers: true, symbols: true, uppercase: true }),
    ITERS,
  );

  printTable('3. Password Generation (10,000 ops each)', [ptResult, gpResult]);
}


// 4. Server-safe hashing (async, fewer iters)
async function benchHashing() {
  const ITERS = 5;
  const PW = 'BenchmarkPassword!99';

  // warm up
  await pbkdf2Hash(PW);
  await bcrypt.hash(PW, 10);

  const ptResult = await benchAsync(
    'passwordthing pbkdf2Hash (SHA-256, 600k)',
    () => pbkdf2Hash(PW),
    ITERS,
  );

  // bcrypt cost 10 is typical production default
  const bcResult = await benchAsync(
    'bcryptjs (cost=10)',
    () => bcrypt.hash(PW, 10),
    ITERS,
  );

  // bcrypt cost 12
  const bc12Result = await benchAsync(
    'bcryptjs (cost=12)',
    () => bcrypt.hash(PW, 12),
    ITERS,
  );

  printTable(`4. Server-safe Hashing (${ITERS} ops each, intentionally slow)`, [ptResult, bcResult, bc12Result]);
  console.log('\nNote: slower = harder to brute-force. PBKDF2-600k and bcrypt-12 are both');
  console.log('      OWASP-recommended. Pick based on your stack, not raw speed.');
}


// Main
console.log('passwordthing performance benchmark');
console.log('====================================');
console.log('Node', process.version, '|', process.arch, '|', new Date().toISOString());

benchValidation();
benchStrength();
benchGenerate();
await benchHashing();

console.log('\nDone.\n');
