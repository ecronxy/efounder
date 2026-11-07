// Cross-checks the dependency-free implementation against the reference libraries:
//   @ton/crypto — mnemonic validity + key derivation
//   @ton/core   — cell building / hashing
//   @ton/ton    — WalletContractV4 (code, wallet id, state init, address)
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mnemonicValidate, mnemonicToPrivateKey } from '@ton/crypto';
import { WalletContractV4 } from '@ton/ton';
import { beginCell } from '@ton/core';
import {
  V4R2_CODE_HASH,
  V4R2_CODE_DEPTH,
  WALLET_V4R2_WALLET_ID,
  wordsFromRandom,
  entropyOf,
  isValidPasswordless,
  seedFromEntropy,
  publicKeyFromSeed,
  v4R2DataCellHash,
  v4R2AddressHash,
  friendlyAddress,
} from '../lib/ton.mjs';

function randomWords() {
  const buf = Buffer.alloc(36);
  crypto.randomFillSync(buf.subarray(0, 33));
  return wordsFromRandom(buf);
}

function validRandomWords() {
  for (;;) {
    const words = randomWords();
    if (isValidPasswordless(entropyOf(words))) return words;
  }
}

// 1. the hardcoded code hash is the real v4 r2 code cell hash
{
  const contract = WalletContractV4.create({ workchain: 0, publicKey: Buffer.alloc(32, 7) });
  assert.ok(contract.init.code.hash().equals(V4R2_CODE_HASH), 'code hash mismatch');
  assert.equal(contract.init.code.depth(), V4R2_CODE_DEPTH, 'code depth mismatch');
}

// 2. mnemonic validity agrees with @ton/crypto on random draws
for (let i = 0; i < 150; i++) {
  const words = randomWords();
  const mine = isValidPasswordless(entropyOf(words));
  const ref = await mnemonicValidate(words);
  assert.equal(mine, ref, `validity mismatch: ${words.join(' ')}`);
}

// 3. addresses agree with @ton/ton for valid mnemonics (both UQ and EQ forms)
for (let i = 0; i < 20; i++) {
  const words = validRandomWords();
  const ref = await mnemonicToPrivateKey(words);
  const publicKey = Buffer.from(ref.publicKey);
  const contract = WalletContractV4.create({ workchain: 0, publicKey });
  const hash = v4R2AddressHash(publicKeyFromSeed(seedFromEntropy(entropyOf(words))));
  assert.equal(
    friendlyAddress(hash, false),
    contract.address.toString({ urlSafe: true, bounceable: false }),
    'non-bounceable address mismatch for: ' + words.join(' ')
  );
  assert.equal(
    friendlyAddress(hash, true),
    contract.address.toString({ urlSafe: true, bounceable: true }),
    'bounceable address mismatch for: ' + words.join(' ')
  );
}

// 4. data cell hash agrees with a cell built by @ton/core
for (let i = 0; i < 3; i++) {
  const words = validRandomWords();
  const ref = await mnemonicToPrivateKey(words);
  const publicKey = Buffer.from(ref.publicKey);
  const dataCell = beginCell()
    .storeUint(0, 32)
    .storeUint(WALLET_V4R2_WALLET_ID, 32)
    .storeBuffer(publicKey)
    .storeBit(0)
    .endCell();
  assert.ok(dataCell.hash().equals(v4R2DataCellHash(publicKey)), 'data cell hash mismatch');
}

console.log('reference test: all checks passed');
