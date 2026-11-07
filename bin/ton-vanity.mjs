#!/usr/bin/env node
// ton-vanity — generate a TON wallet whose address contains your pattern.
// Everything runs locally: the seed phrase never leaves this machine.
import { Worker } from 'node:worker_threads';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VERSION = '1.0.0';

const usage = `
ton-vanity — generate a TON wallet whose address contains your pattern.
Everything runs locally: the seed phrase never leaves this machine.

usage:
  ton-vanity <suffix> [options]
  ton-vanity -p <prefix> -s <suffix> [options]

the pattern is matched against the Tonkeeper-style address (UQ..., base64url).
matching is case-insensitive by default (much faster); use --case-sensitive for exact.

options:
  -s, --suffix <text>      address must end with this
  -p, --prefix <text>      address must start with this (right after UQ)
  -t, --threads <n>        worker threads (default: all CPU threads)
      --case-sensitive     require exact case
      --json               print the final result as one JSON line
  -o, --out <file>         save result to this file (default: ./found-<pattern>-<date>.txt)
  -h, --help
  -v, --version

examples:
  ton-vanity sexy
  ton-vanity --prefix sexy --case-sensitive
  ton-vanity -s sexy -t 8 --json
`;

function fail(msg) {
  console.error('ton-vanity: ' + msg);
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
  out: '',
};
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  const val = () => {
    const v = argv[++i];
    if (v === undefined) fail(a + ' needs a value');
    return v;
  };
  if (a === '-h' || a === '--help') { console.log(usage); process.exit(0); }
  else if (a === '-v' || a === '--version') { console.log(VERSION); process.exit(0); }
  else if (a === '-s' || a === '--suffix') opts.suffix = val();
  else if (a === '-p' || a === '--prefix') opts.prefix = val();
  else if (a === '-t' || a === '--threads') opts.threads = Number.parseInt(val(), 10);
  else if (a === '--case-sensitive') opts.caseSensitive = true;
  else if (a === '--json') opts.json = true;
  else if (a === '-o' || a === '--out') opts.out = val();
  else if (a.startsWith('-')) fail('unknown option: ' + a);
  else if (opts.suffix) fail('only one positional pattern is allowed (use -p for the prefix)');
  else opts.suffix = a;
}
if (!opts.prefix && !opts.suffix) { console.log(usage); process.exit(0); }
if (!Number.isFinite(opts.threads) || opts.threads < 1) fail('--threads must be a positive number');
for (const [name, value] of [['prefix', opts.prefix], ['suffix', opts.suffix]]) {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) fail(name + ' may only contain base64url characters: A-Z a-z 0-9 - _');
}
if (opts.prefix.length + opts.suffix.length > 47) fail('pattern is too long');

// --- vanity math ---
const pattern = opts.prefix + opts.suffix;
function expectedAttempts() {
  const total = 64n ** BigInt(pattern.length);
  if (opts.caseSensitive) return total;
  let letters = 0;
  for (const c of pattern) if (/[A-Za-z]/.test(c)) letters++;
  return total >> BigInt(letters); // / 2^letters: both cases accepted per letter
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

function spawnWorkers() {
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
    const rate = winMs > 0 ? (winValid / winMs) * 1000 : 0;
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
      words: found.words,
      savedTo: file,
    }));
  } else {
    const words = found.words;
    const width = Math.max(...words.map((w) => w.length));
    console.log(`\n\n  found after ${fmtCount(attempts)} attempts (${fmtTime(elapsed)})\n`);
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
    'TON vanity wallet (wallet v4 r2, mainnet, generated locally by ton-vanity)',
    'generated: ' + new Date().toISOString(),
    'attempts:  ' + attempts,
    '',
    'address (Tonkeeper, non-bounceable): ' + m.address,
    'address (bounceable):                ' + m.bounceable,
    '',
    'seed phrase (24 words, order matters):',
    ...m.words.map((w, i) => `${i + 1}. ${w}`),
    '',
    'WARNING: anyone who reads these 24 words controls the wallet.',
    'Store this file somewhere safe and delete it from disk afterwards.',
  ];
  fs.writeFileSync(file, lines.join('\n') + '\n', { mode: 0o600 });
  return file;
}

spawnWorkers();
startTicker();
process.on('SIGINT', () => {
  if (ticker) clearInterval(ticker);
  if (!opts.json) process.stdout.write(`\n  stopped after ${fmtCount(attempts)} attempts\n`);
  for (const w of workers) w.terminate();
  process.exit(130);
});
