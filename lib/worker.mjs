// Search worker: derive wallets from random 24-word phrases until one matches the pattern.
import { parentPort, workerData } from 'node:worker_threads';
import crypto from 'node:crypto';
import {
  wordsFromRandom,
  entropyOf,
  isBasicSeed,
  seedFromEntropy,
  publicKeyFromSeed,
  WALLETS,
  walletAddressHash,
  friendlyAddress,
} from './ton.mjs';

const { prefix = '', suffix = '', caseSensitive = false, reportMs = 1000 } = workerData;

const fold = (s) => (caseSensitive ? s : s.toLowerCase());
const pre = prefix ? fold(prefix) : '';
const suf = suffix ? fold(suffix) : '';

const rnd = Buffer.alloc(36); // 33 random bytes + zero tail (see wordsFromRandom)
const randomPart = rnd.subarray(0, 33);
let attempts = 0; // raw phrase draws
let valid = 0; // draws that passed the checksum and got a full address derivation
let lastReport = performance.now();

while (true) {
  crypto.randomFillSync(randomPart);
  const words = wordsFromRandom(rnd);
  const entropy = entropyOf(words);
  if (isBasicSeed(entropy)) {
    valid++;
    const publicKey = publicKeyFromSeed(seedFromEntropy(entropy));
    let hit = null;
    for (const wallet of WALLETS) {
      const hash = walletAddressHash(wallet, publicKey);
      const addr = fold(friendlyAddress(hash));
      // the prefix is matched right after the fixed "UQ" tag
      if ((!pre || addr.startsWith(pre, 2)) && (!suf || addr.endsWith(suf))) {
        hit = { wallet, hash };
        break;
      }
    }
    if (!hit) {
      attempts++;
    } else {
      parentPort.postMessage({
        type: 'found',
        attempts: attempts + 1,
        valid,
        version: hit.wallet.name,
        address: friendlyAddress(hit.hash, false),
        bounceable: friendlyAddress(hit.hash, true),
        words,
      });
      break;
    }
  } else {
    attempts++;
  }
  const now = performance.now();
  if (now - lastReport >= reportMs) {
    parentPort.postMessage({ type: 'progress', attempts, valid, ms: now - lastReport });
    attempts = 0;
    valid = 0;
    lastReport = now;
  }
}
