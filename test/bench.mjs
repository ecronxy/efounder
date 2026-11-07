// Measures the real search rate of this machine and projects average run times.
import { Worker } from 'node:worker_threads';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SECONDS = 15;
const threads = os.cpus().length;

let attempts = 0; // raw draws
let valid = 0; // full address derivations
const workers = [];
for (let i = 0; i < threads; i++) {
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
const validRate = valid / elapsed; // what actually matters: addresses checked per second
console.log(`threads: ${threads}, elapsed: ${elapsed.toFixed(1)}s`);
console.log(`draws: ${drawRate.toFixed(0)}/s (phrases tried), valid: ${valid.toFixed(0)} (${validRate.toFixed(1)}/s full derivations)`);
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
  const hours = expected / validRate / 3600;
  console.log(`  ${label}: ~${hours >= 1 ? hours.toFixed(1) + ' h' : (hours * 60).toFixed(1) + ' min'}`);
}
process.exit(0);
