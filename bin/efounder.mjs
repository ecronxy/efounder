#!/usr/bin/env node
// eFounder — generate a TON wallet whose address contains your pattern.
// Everything runs locally: the seed phrase never leaves this machine.
import { Worker } from 'node:worker_threads';
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { banner } from '../lib/banner.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VERSION = '1.0.0';

const usage = `
eFounder — generate a TON wallet whose address contains your pattern.
Everything runs locally: the seed phrase never leaves this machine.

usage:
  efounder <suffix> [options]
  efounder -p <prefix> -s <suffix> [options]

the pattern is matched against the Tonkeeper-style address (UQ..., base64url).
matching is case-insensitive by default (much faster); use --case-sensitive for exact.

options:
  -s, --suffix <text>      address must end with this
  -p, --prefix <text>      address must start with this, right after UQ
                           (first char must be A, B, C or D: every TON
                           address starts with UQA, UQB, UQC or UQD)
  -t, --threads <n>        worker threads (default: all CPU threads)
      --case-sensitive     require exact case
      --json               print the final result as one JSON line
      --js                 use the pure-JS engine even if the native one is built
  -o, --out <file>         save result to this file (default: ./found-<pattern>-<date>.txt)
  -h, --help
  -v, --version

examples:
  efounder sexy
  efounder --prefix Cool --case-sensitive
  efounder -s sexy -t 8 --json
`;

function fail(msg) {
  console.error('efounder: ' + msg);
  process.exit(1);
}

// --- args ---
const argv = process.argv.slice(2);
const opts = {
  prefix: '',
  suffix: '',
  threads: Math.max(1, os.cpus().length),
  caseSensitive: false,
  json: false,
  js: false,
  out: '',
};
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  const val = () => {
    const v = argv[++i];
    if (v === undefined) fail(a + ' needs a value');
    return v;
  };
  if (a === '-h' || a === '--help') { console.log(banner() + usage); process.exit(0); }
  else if (a === '-v' || a === '--version') { console.log(VERSION); process.exit(0); }
  else if (a === '-s' || a === '--suffix') opts.suffix = val();
  else if (a === '-p' || a === '--prefix') opts.prefix = val();
  else if (a === '-t' || a === '--threads') opts.threads = Number(val());
  else if (a === '--case-sensitive') opts.caseSensitive = true;
  else if (a === '--json') opts.json = true;
  else if (a === '--js') opts.js = true;
  else if (a === '-o' || a === '--out') opts.out = val();
  else if (a.startsWith('-')) fail('unknown option: ' + a);
  else if (opts.suffix) fail('only one positional pattern is allowed (use -p for the prefix)');
  else opts.suffix = a;
}
if (!opts.prefix && !opts.suffix) { console.log(banner() + usage); process.exit(0); }
if (!Number.isInteger(opts.threads) || opts.threads < 1) fail('--threads must be a positive integer');
// "-p UQCool" and "-p Cool" mean the same thing
if (/^uq/i.test(opts.prefix)) opts.prefix = opts.prefix.slice(2);
for (const [name, value] of [['prefix', opts.prefix], ['suffix', opts.suffix]]) {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) fail(name + ' may only contain base64url characters: A-Z a-z 0-9 - _');
}
if (opts.prefix && !(opts.caseSensitive ? /^[A-D]/ : /^[A-Da-d]/).test(opts.prefix)) {
  fail(
    `prefix "${opts.prefix}" is impossible: the character right after UQ is always A, B, C or D ` +
      `(it encodes the workchain). try -p ${opts.caseSensitive ? 'C' : 'c'}${opts.prefix} or use a suffix`
  );
}
// 48 chars total, "UQ" is fixed
if (opts.prefix.length + opts.suffix.length > 46) fail('pattern is too long (max 46 chars after UQ)');

// --- vanity math ---
// odds per char: 1/64 exact, 1/32 for a letter matched in any case,
// 1/4 for the first prefix char (only A-D can appear there)
function expectedAttempts() {
  let total = 1n;
  const chars = [...opts.prefix].map((c, i) => [c, i === 0]).concat([...opts.suffix].map((c) => [c, false]));
  for (const [c, first] of chars) {
    if (first) total *= 4n;
    else total *= !opts.caseSensitive && /[A-Za-z]/.test(c) ? 32n : 64n;
  }
  return total;
}
function fmtCount(n) {
  if (typeof n === 'number') return fmtCount(BigInt(Math.max(0, Math.round(n))));
  const units = [
    [10n ** 24n, 'Y'], [10n ** 21n, 'Z'], [10n ** 18n, 'E'],
    [10n ** 15n, 'P'], [10n ** 12n, 'T'], [10n ** 9n, 'B'],
    [10n ** 6n, 'M'], [1000n, 'k'],
  ];
  for (const [div, u] of units) {
    if (n >= div) {
      const frac = ((n % div) * 100n) / div;
      return `${n / div}.${frac.toString().padStart(2, '0')}${u}`;
    }
  }
  return n.toString();
}
function fmtTime(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return '?';
  for (const [div, u] of [[31557600, 'y'], [86400, 'd'], [3600, 'h'], [60, 'm']]) {
    if (seconds >= div) return (seconds / div).toFixed(1) + u;
  }
  return Math.round(seconds) + 's';
}

// --- workers ---
const workers = [];
let found = null;
let attempts = 0; // raw draws
let valid = 0; // full address derivations (1/256 of draws on average)
let winValid = 0;
let winMs = 0;
const startedAt = performance.now();

// AVX2 core from native/ (npm run build), ~4x faster than the JS workers
const NATIVE = path.join(__dirname, '../native/ton-vanity-native');

function spawnNative() {
  const child = spawn(NATIVE, [String(opts.threads), opts.prefix, opts.suffix, opts.caseSensitive ? '1' : '0'], {
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  let buf = '';
  child.stdout.on('data', (chunk) => {
    buf += chunk;
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const [type, ...f] = buf.slice(0, nl).split(' ');
      buf = buf.slice(nl + 1);
      if (type === 'progress') {
        onMessage({ type, attempts: Number(f[0]), valid: Number(f[1]), ms: Number(f[2]) });
      } else if (type === 'found') {
        onMessage({
          type,
          attempts: Number(f[0]),
          valid: Number(f[1]),
          version: f[2],
          address: f[3],
          bounceable: f[4],
          words: f.slice(5),
        });
      }
    }
  });
  child.on('exit', (code) => {
    if (!found) {
      console.error(`native engine exited with code ${code}; retry with --js`);
      process.exit(1);
    }
  });
  workers.push({ terminate: () => child.kill() });
}

function spawnWorkers() {
  if (!opts.js && fs.existsSync(NATIVE)) return spawnNative();
  for (let i = 0; i < opts.threads; i++) {
    const worker = new Worker(path.join(__dirname, '../lib/worker.mjs'), {
      workerData: {
        prefix: opts.prefix,
        suffix: opts.suffix,
        caseSensitive: opts.caseSensitive,
        reportMs: 1000,
      },
    });
    worker.on('message', onMessage);
    worker.on('error', (err) => {
      console.error('worker error: ' + err.message);
      process.exit(1);
    });
    workers.push(worker);
  }
}

function onMessage(m) {
  if (m.type === 'progress') {
    attempts += m.attempts;
    valid += m.valid;
    winValid += m.valid;
    winMs += m.ms;
  } else if (m.type === 'found') {
    if (found) return;
    found = m;
    attempts += m.attempts;
    valid += m.valid;
    finish();
  }
}

let ticker = null;
function startTicker() {
  if (opts.json) return;
  ticker = setInterval(() => {
    // ETA uses the valid-derivation rate: the pattern is only checked
    // against addresses of phrases that pass TON's 1/256 checksum.
    // every valid phrase is checked as 4 wallet versions (v3R1, v3R2, v4R2, W5)
    const rate = winMs > 0 ? (winValid / winMs) * 1000 * 4 : 0;
    const elapsed = (performance.now() - startedAt) / 1000;
    const need = Number(expectedAttempts());
    const eta = rate > 0 ? need / rate : Infinity;
    process.stdout.write(
      `\r  ${fmtTime(elapsed).padStart(7)}  ${fmtCount(rate)} addr/s` +
      `  tried ${fmtCount(attempts)}  eta ~${fmtTime(eta)}   `
    );
    winValid = 0;
    winMs = 0;
  }, 1000);
}

function finish() {
  if (ticker) clearInterval(ticker);
  for (const w of workers) w.terminate();
  const elapsed = (performance.now() - startedAt) / 1000;
  const file = saveResult(found);
  if (opts.json) {
    console.log(JSON.stringify({
      found: true,
      attempts,
      elapsedSec: Math.round(elapsed),
      address: found.address,
      bounceableAddress: found.bounceable,
      walletVersion: found.version,
      words: found.words,
      savedTo: file,
    }));
  } else {
    const words = found.words;
    const width = Math.max(...words.map((w) => w.length));
    console.log(`\n\n  found after ${fmtCount(attempts)} attempts (${fmtTime(elapsed)})\n`);
    console.log(`  wallet version:       ${found.version}`);
    console.log(`  address (Tonkeeper):  ${found.address}`);
    console.log(`  bounceable:           ${found.bounceable}\n`);
    console.log('  seed phrase (24 words, order matters):\n');
    for (let r = 0; r < 6; r++) {
      const row = [0, 1, 2, 3]
        .map((c) => {
          const i = r * 4 + c;
          return `${String(i + 1).padStart(2)}. ${words[i].padEnd(width)}`;
        })
        .join('   ');
      console.log('    ' + row.trimEnd());
    }
    console.log(`\n  Tonkeeper: import with these 24 words, then pick wallet version ${found.version}`);
    console.log('  (other versions of the same words have different addresses).');
    console.log('\n  anyone who reads these 24 words owns the wallet. write them down.');
    console.log(`  saved to: ${file} (chmod 600)\n`);
  }
  process.exit(0);
}

function saveResult(m) {
  const file = path.resolve(
    opts.out ||
      `found-${(opts.prefix + opts.suffix || 'address').replace(/[^A-Za-z0-9_-]/g, '')}-${new Date()
        .toISOString()
        .replace(/[:.]/g, '-')}.txt`
  );
  const lines = [
    `TON vanity wallet (wallet ${m.version}, mainnet, generated locally by eFounder, ecronx.t.me)`,
    'generated: ' + new Date().toISOString(),
    'attempts:  ' + attempts,
    '',
    'address (Tonkeeper, non-bounceable): ' + m.address,
    'address (bounceable):                ' + m.bounceable,
    '',
    'seed phrase (24 words, order matters):',
    ...m.words.map((w, i) => `${i + 1}. ${w}`),
    '',
    `Tonkeeper: import with these 24 words and pick wallet version ${m.version}`,
    '(other versions of the same words have different addresses).',
    '',
    'WARNING: anyone who reads these 24 words controls the wallet.',
    'Store this file somewhere safe and delete it from disk afterwards.',
  ];
  fs.writeFileSync(file, lines.join('\n') + '\n', { mode: 0o600 });
  return file;
}

if (!opts.json) console.log(banner());
spawnWorkers();
startTicker();
process.on('SIGINT', () => {
  if (ticker) clearInterval(ticker);
  if (!opts.json) process.stdout.write(`\n  stopped after ${fmtCount(attempts)} attempts\n`);
  for (const w of workers) w.terminate();
  process.exit(130);
});
