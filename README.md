# ton-vanity

Generate TON wallet addresses with a pattern you choose (vanity addresses), **locally**. The result is a standard 24-word seed phrase — import it into Tonkeeper or any TON wallet and use it like any other wallet.

Everything happens on your machine: no servers, no network requests, the seed phrase never leaves the process.

## How it works

A TON address is derived from the wallet's public key, so the only way to get a specific ending is brute force: draw random 24-word phrases, derive the wallet v4 r2 address, check the pattern.

Two properties of TON make this slower than Ethereum-style vanity generation:

- **probabilistic checksum** — only ~1 of 256 random phrases is a *valid* TON mnemonic (`is_basic_seed` in tonlib), so ~255 of 256 draws are discarded before the expensive key derivation;
- **PBKDF2** — every surviving candidate costs PBKDF2-HMAC-SHA512 with 100,000 iterations, exactly as in tonlib and Tonkeeper.

The generated wallet is the standard **v4 r2** contract (`walletId 698983191`) — what Tonkeeper uses when you import a 24-word seed. Patterns are matched against the **non-bounceable `UQ...`** form, which is what Tonkeeper displays.

The runtime is dependency-free (Node stdlib only) and is verified byte-for-byte against `@ton/crypto`, `@ton/core` and `@ton/ton` in the reference test.

## Install

Requires Node.js >= 18. Nothing to install for the runtime.

```bash
# from the project folder:
node bin/ton-vanity.mjs --help
# or make it a global command:
npm i -g . && ton-vanity --help
```

## Usage

```bash
ton-vanity sexy                      # suffix, case-insensitive (default)
ton-vanity --suffix sexy --case-sensitive
ton-vanity -p UQsexy                 # prefix instead of suffix
ton-vanity -s money -t 8             # limit worker threads
ton-vanity -s sexy --json            # machine-readable single-line result
```

Options:

| flag | meaning |
|---|---|
| `-s, --suffix <text>` | address must end with this |
| `-p, --prefix <text>` | address must start with this (right after `UQ`) |
| `-t, --threads <n>` | worker threads (default: all CPU threads) |
| `--case-sensitive` | exact case match |
| `--json` | final result as one JSON line |
| `-o, --out <file>` | save result to this file |

On success it prints the address and the 24 words, and saves everything to `found-<pattern>-<date>.txt` with `chmod 600`. `found-*` is gitignored so seeds never get committed.

## Performance

Measured on a 4-core / 8-thread laptop (i5-class), PBKDF2-bound:

| pattern | expected tries (average) | time on this laptop |
|---|---|---|
| 3 chars, any case | 32,768 | ~45 min |
| 3 chars, exact case | 262,144 | ~6 h |
| 4 chars, any case (`sexy`) | 1,048,576 | ~24 h |
| 4 chars, exact case (`sexy`) | 16,777,216 | ~16 days |
| 5 chars, any case | 1,048,576 | ~24 h |

Notes:

- Case-insensitive matching (the default) accepts both cases per letter and is 2^letters faster; use `--case-sensitive` for exact.
- "Expected tries" is an average — variance is high, a hit can come 10x earlier or later.
- Scaling is linear: run the tool on several machines at once, no coordination needed (independent random streams), first hit wins. A 16-core VPS roughly halves these times.

## Security

- Phrases are generated from the OS CSPRNG in memory; results are written locally with `0600`.
- Never trust online vanity generators: whoever generates your phrase knows your private key. This tool is a few hundred lines you can actually read.
- After importing the phrase into your wallet, delete the `found-*.txt` file.

## Tests

```bash
npm i        # dev deps only, used by the reference test
npm test     # cross-checks vs @ton/crypto, @ton/core, @ton/ton
npm run bench
```

## License

MIT
