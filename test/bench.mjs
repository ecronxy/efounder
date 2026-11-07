// Measures the real search rate of this machine and projects average run times.
import { Worker } from 'node:worker_threads';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SECONDS = 15;
const threads = os.cpus().length;

let attempts = 0; // raw draws
let valid = 0; // full address derivations
const workers = [];
// same engine choice as the CLI: native core if built, --js forces the workers
const NATIVE = path.join(__dirname, '../native/ton-vanity-native');
const native = !process.argv.includes('--js') && fs.existsSync(NATIVE);
if (native) {
  const child = spawn(NATIVE, [String(threads), '', 'z'.repeat(46), '1'], { stdio: ['ignore', 'pipe', 'inherit'] });
  child.stdout.on('data', (chunk) => {
    for (const line of String(chunk).trim().split('\n')) {
      const [type, a, v] = line.split(' ');
      if (type === 'progress') {
        attempts += Number(a);
        valid += Number(v);
      }
    }
  });
  workers.push({ terminate: async () => child.kill() });
}
for (let i = 0; i < (native ? 0 : threads); i++) {
  // impossible pattern: exercises the full pipeline without ever matching
  const w = new Worker(path.join(__dirname, '../lib/worker.mjs'), {
    workerData: { suffix: 'z'.repeat(47), reportMs: 1000 },
  });
  w.on('message', (m) => {
    if (m.type === 'progress') {
      attempts += m.attempts;
      valid += m.valid;
    }
  });
  w.on('error', (e) => console.error('worker error:', e));
  workers.push(w);
}

const t0 = performance.now();
await new Promise((r) => setTimeout(r, SECONDS * 1000));
for (const w of workers) w.terminate().catch(() => {});

const elapsed = (performance.now() - t0) / 1000;
const drawRate = attempts / elapsed;
const validRate = valid / elapsed;
const addrRate = validRate * 4; // what actually matters: each valid phrase = 4 wallet versions
console.log(`engine: ${native ? 'native AVX2' : 'js'}, threads: ${threads}, elapsed: ${elapsed.toFixed(1)}s`);
console.log(`draws: ${drawRate.toFixed(0)}/s (phrases tried), valid: ${valid.toFixed(0)} (${validRate.toFixed(1)}/s full derivations, ${addrRate.toFixed(1)} addresses/s)`);
console.log(`~1 valid phrase per ${(256).toFixed(0)} draws`);
console.log('average time to hit:');
for (const [len, letters, label] of [
  [3, 0, '3 chars, exact case'],
  [3, 3, '3 chars, any case   '],
  [4, 0, '4 chars, exact case'],
  [4, 4, '4 chars, any case   '],
  [5, 5, '5 chars, any case   '],
]) {
  const expected = 64 ** len / 2 ** letters;
  const hours = expected / addrRate / 3600;
  console.log(`  ${label}: ~${hours >= 1 ? hours.toFixed(1) + ' h' : (hours * 60).toFixed(1) + ' min'}`);
}
process.exit(0);
