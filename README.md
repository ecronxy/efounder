<p align="center">
  <img src="docs/banner.svg" alt="eFounder" width="720">
</p>

<p align="center">
  Vanity TON wallet addresses, generated locally.<br>
  A normal 24-word seed phrase that imports into Tonkeeper, with the address ending you want.
</p>

<p align="center">
  by <a href="https://ecronx.t.me">ecronx.t.me</a>
</p>

---

```
$ efounder moka

  wallet version:       W5
  address (Tonkeeper):  UQ…moka
```

- **Local.** No servers, no network requests. The seed phrase never leaves your machine.
- **Tonkeeper-compatible.** Standard 24-word mnemonic, standard wallet contracts, verified byte-for-byte against `@ton/crypto` and `@ton/ton`.
- **Fast on a plain CPU.** AVX2 core computes 4 phrases at once, and every phrase is checked as 4 wallet versions.

## Install

Requires Node.js 18+.

```bash
git clone https://github.com/ecronxy/efounder
cd efounder
npm run build      # optional: native AVX2 core, ~4x faster (Linux, gcc or clang + OpenSSL headers)
npm i -g .         # optional: the `efounder` command everywhere
```

Without the native core the CLI falls back to pure JS with zero runtime dependencies. On Windows `npm run build` is skipped and the JS engine is used; for the fast core run eFounder inside WSL.

## Usage

```bash
efounder sexy                     # address ends with "sexy", any case
efounder sexy --case-sensitive    # exactly "sexy"
efounder -p UQCool                # address starts with "UQCool"
efounder -s money -t 4            # use 4 threads
efounder -s sexy --json           # one JSON line, for scripts
```

| option | meaning |
|---|---|
| `-s, --suffix <text>` | address ends with this (also the positional argument) |
| `-p, --prefix <text>` | address starts with this, right after `UQ` |
| `-t, --threads <n>` | worker threads, default: all CPU threads |
| `--case-sensitive` | exact case match |
| `--json` | print the result as one JSON line |
| `--js` | use the pure-JS engine even if the native core is built |
| `-o, --out <file>` | where to save the result |

Patterns use base64url characters: `A-Z a-z 0-9 - _`. Every TON address starts with `UQA`, `UQB`, `UQC` or `UQD`, so the first prefix character must be `A`-`D`.

The result is printed and saved to `found-<pattern>-<date>.txt` with `chmod 600`.

## Import into Tonkeeper

1. Import the wallet with the 24 words.
2. Pick the wallet version printed in the result: `v3R1`, `v3R2`, `v4R2` or `W5`.

The same 24 words give a different address in each version, so only the printed one is your vanity address. For everyday use (TON, tokens, NFTs, dapps) the versions behave the same; W5 additionally supports paying fees in USDT and batch transfers.

## Speed

Measured on a 4-core / 8-thread laptop (Intel i5-10310U): **~166 addresses/s** with the native core, ~38/s in pure JS. Average time to a hit:

| pattern | average tries | native | pure JS |
|---|---|---|---|
| 3 chars, any case | 32,768 | ~3 min | ~14 min |
| 3 chars, exact case | 262,144 | ~26 min | ~1.9 h |
| 4 chars, any case | 1,048,576 | ~1.7 h | ~7.7 h |
| 4 chars, exact case | 16,777,216 | ~28 h | ~5 days |
| 5 chars, any case | 33,554,432 | ~2.3 days | ~10 days |

- Any case (the default) is 2× faster per letter than `--case-sensitive`.
- These are averages. Luck matters a lot: a hit can come 10× earlier or later.
- Stopping loses nothing. Every attempt is independent, so you can stop and restart any time, or run on several machines at once.
- `npm run bench` measures your machine.

## How it works

A TON address is a hash of the wallet contract, which includes the public key. The only way to get a chosen ending is to try random phrases until one fits. Each try costs:

1. **Checksum.** Only ~1 in 256 random phrases is a valid TON mnemonic (`is_basic_seed` in tonlib), checked with PBKDF2-HMAC-SHA512 × 390.
2. **Key derivation.** PBKDF2-HMAC-SHA512 × 100,000, exactly as in tonlib and Tonkeeper.
3. **Addresses.** Ed25519 public key, then the StateInit hash of 4 wallet contracts: v3R1, v3R2, v4R2 and W5. This part is nearly free, so one phrase gives 4 chances.

PBKDF2 is 99% of the work. The native core in `native/` runs it for 4 phrases at once in AVX2 registers, with precomputed HMAC pad states, about 4.4× faster than OpenSSL's one-at-a-time PBKDF2. Addresses are matched in the non-bounceable `UQ...` form that Tonkeeper shows.

## Security

- Phrases come from the OS CSPRNG and stay in memory; results are written locally with `0600`.
- Never use online vanity generators: whoever generates the phrase knows your private key.
- The code is small enough to read before you trust it.
- After importing the wallet, delete the `found-*.txt` file. `found-*` is gitignored.

## Tests

```bash
npm i       # dev dependencies, only for the reference test
npm test    # JS and native core vs @ton/crypto, @ton/core, @ton/ton
npm run bench
```

## License

MIT © [ecronx](https://ecronx.t.me)
