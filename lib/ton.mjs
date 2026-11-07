// TON wallet v4 r2 derivation, dependency-free.
// Matches @ton/crypto (mnemonics) and @ton/core (cell hashing); verified by test/reference.test.mjs.
import crypto from 'node:crypto';
import { WORDLIST } from './wordlist.mjs';

// Canonical wallet v4 r2 code cell hash (mainnet). Confirmed by TON block explorers
// and re-checked against @ton/ton WalletContractV4 in the reference test.
export const V4R2_CODE_HASH = Buffer.from(
  'feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0',
  'hex'
);
// The v4 r2 code BOC root cell has one child cell, so its max depth is 7 —
// this value goes into the StateInit representation (ref depth field).
export const V4R2_CODE_DEPTH = 7;
export const WALLET_V4R2_WALLET_ID = 698983191; // basechain, mainnet

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

// 264 random bits -> 24 wordlist words, 11 bits per index, MSB first.
// `buf` must be at least 35 readable bytes; only the first 33 are random data.
export function wordsFromRandom(buf) {
  const words = new Array(24);
  for (let i = 0; i < 24; i++) {
    const bit = i * 11;
    const byte = bit >> 3;
    const shift = bit & 7;
    const v = (buf[byte] << 16) | (buf[byte + 1] << 8) | buf[byte + 2];
    words[i] = WORDLIST[(v >> (13 - shift)) & 2047];
  }
  return words;
}

// entropy = HMAC-SHA512(joined words, password), passwordless here (matches tonlib Mnemonic::to_entropy)
export function entropyOf(words) {
  return crypto.createHmac('sha512', words.join(' ')).update('').digest();
}

export function isPasswordSeed(entropy) {
  return crypto.pbkdf2Sync(entropy, 'TON fast seed version', 1, 64, 'sha512')[0] === 1;
}

export function isBasicSeed(entropy) {
  return crypto.pbkdf2Sync(entropy, 'TON seed version', Math.max(1, Math.floor(100000 / 256)), 64, 'sha512')[0] === 0;
}

// A phrase imports into wallets without a password iff it is a basic seed
// (is_basic_seed in tonlib — TON's probabilistic mnemonic checksum; only ~1/256
// of random word draws pass, which is why vanity search has to burn through them).
export function isValidPasswordless(entropy) {
  return isBasicSeed(entropy);
}

export function seedFromEntropy(entropy) {
  return crypto.pbkdf2Sync(entropy, 'TON default seed', 100000, 64, 'sha512').subarray(0, 32);
}

export function publicKeyFromSeed(seed) {
  const priv = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const spki = crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' });
  return spki.subarray(spki.length - 32);
}

// Data cell of wallet v4 r2: seqno(32) wallet_id(32) public_key(256) + 1 bit (empty plugins dict).
// 321 bits -> bits descriptor d2 = ceil(321/8) + floor(321/8) = 81; trailing byte 0x80 = dict bit + completion tag.
export function v4R2DataCellHash(publicKey, walletId = WALLET_V4R2_WALLET_ID) {
  const repr = Buffer.alloc(2 + 41);
  repr[0] = 0x00; // refs descriptor: ordinary, level 0, 0 refs
  repr[1] = 81; // bits descriptor
  repr.writeUInt32BE(0, 2); // seqno
  repr.writeUInt32BE(walletId, 6);
  publicKey.copy(repr, 10);
  repr[42] = 0x40; // data bit 0 + completion tag bit 1 (bitsToPaddedBuffer)
  return crypto.createHash('sha256').update(repr).digest();
}

// Address = SHA-256 of the StateInit cell.
// Data bits: split_depth=0, special=0, code present=1, data present=1, libs dict empty=0
//   -> 5 bits 0b00110, padded last byte 0x34, bits descriptor = ceil(5/8) + floor(5/8) = 1.
// Refs section: depths of ALL refs first (code depth 7, data depth 0), then hashes of all refs.
export function v4R2AddressHash(publicKey, walletId = WALLET_V4R2_WALLET_ID) {
  const dataHash = v4R2DataCellHash(publicKey, walletId);
  const repr = Buffer.alloc(2 + 1 + (2 + 2) + 64);
  repr[0] = 0x02; // refs descriptor: ordinary, level 0, 2 refs
  repr[1] = 0x01; // bits descriptor
  repr[2] = 0x34; // data bits 0b00110 + completion tag
  repr[3] = V4R2_CODE_DEPTH >> 8; // code ref max depth (big endian)
  repr[4] = V4R2_CODE_DEPTH & 0xff;
  repr[5] = 0x00; // data ref max depth
  repr[6] = 0x00;
  V4R2_CODE_HASH.copy(repr, 7); // code ref hash
  dataHash.copy(repr, 39); // data ref hash
  return crypto.createHash('sha256').update(repr).digest();
}

function crc16xmodem(buf) {
  let crc = 0;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i] << 8;
    for (let b = 0; b < 8; b++) {
      crc = crc & 0x8000 ? (crc << 1) ^ 0x1021 : crc << 1;
      crc &= 0xffff;
    }
  }
  return crc;
}

// User-friendly address: tag byte + workchain + 32-byte hash + crc16-xmodem, base64 (url-safe).
// bounceable=false -> UQ..., the format Tonkeeper displays.
export function friendlyAddress(hash, bounceable = false) {
  const buf = Buffer.alloc(36);
  buf[0] = bounceable ? 0x11 : 0x51;
  buf[1] = 0x00; // basechain
  hash.copy(buf, 2);
  const crc = crc16xmodem(buf.subarray(0, 34));
  buf[34] = crc >> 8;
  buf[35] = crc & 0xff;
  return buf.toString('base64').replaceAll('+', '-').replaceAll('/', '_');
}
