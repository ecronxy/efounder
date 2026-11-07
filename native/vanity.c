// Native search core: same derivation as lib/ton.mjs, with PBKDF2-HMAC-SHA512
// (99% of the cost) computed for 4 phrases at once in AVX2 registers.
//
// usage: ton-vanity-native <threads> <prefix> <suffix> <case-sensitive 0|1>
//        ton-vanity-native emit <n>     (print n valid wallets, for the reference test)
// stdout, one line each:
//   progress <draws> <valid> <ms>
//   found <draws> <valid> <version> <address> <bounceable> <24 words>
//   valid <v3R1 address> <v3R2 address> <v4R2 address> <W5 address> <24 words>
#define _GNU_SOURCE
#include <ctype.h>
#include <immintrin.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include "wordlist.h"

// ---------- 4-way SHA-512 ----------

typedef __m256i v4;
#define ADD(a, b) _mm256_add_epi64(a, b)
#define XOR(a, b) _mm256_xor_si256(a, b)
#define AND(a, b) _mm256_and_si256(a, b)
#define OR(a, b) _mm256_or_si256(a, b)
#define SET1(x) _mm256_set1_epi64x((long long)(x))
#define ROR(x, n) OR(_mm256_srli_epi64(x, n), _mm256_slli_epi64(x, 64 - (n)))
#define SHR(x, n) _mm256_srli_epi64(x, n)
#define BSIG0(a) XOR(XOR(ROR(a, 28), ROR(a, 34)), ROR(a, 39))
#define BSIG1(e) XOR(XOR(ROR(e, 14), ROR(e, 18)), ROR(e, 41))
#define SSIG0(w) XOR(XOR(ROR(w, 1), ROR(w, 8)), SHR(w, 7))
#define SSIG1(w) XOR(XOR(ROR(w, 19), ROR(w, 61)), SHR(w, 6))
#define CH(e, f, g) XOR(AND(e, f), _mm256_andnot_si256(e, g))
#define MAJ(a, b, c) XOR(AND(a, b), AND(c, XOR(a, b)))

static const uint64_t K[80] = {
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
  0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
  0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
  0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
  0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
  0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
  0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
  0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
  0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
  0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
  0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
  0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
  0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
  0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
  0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};
static const uint64_t IV[8] = {
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
  0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

static inline void compress4(v4 s[8], const v4 blk[16]) {
  v4 w[16];
  for (int i = 0; i < 16; i++) w[i] = blk[i];
  v4 a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
#pragma GCC unroll 80
  for (int i = 0; i < 80; i++) {
    v4 wi;
    if (i < 16) {
      wi = w[i];
    } else {
      wi = ADD(ADD(SSIG1(w[(i - 2) & 15]), w[(i - 7) & 15]), ADD(SSIG0(w[(i - 15) & 15]), w[i & 15]));
      w[i & 15] = wi;
    }
    v4 t1 = ADD(ADD(ADD(h, BSIG1(e)), ADD(CH(e, f, g), SET1(K[i]))), wi);
    v4 t2 = ADD(BSIG0(a), MAJ(a, b, c));
    h = g; g = f; f = e; e = ADD(d, t1);
    d = c; c = b; b = a; a = ADD(t1, t2);
  }
  s[0] = ADD(s[0], a); s[1] = ADD(s[1], b); s[2] = ADD(s[2], c); s[3] = ADD(s[3], d);
  s[4] = ADD(s[4], e); s[5] = ADD(s[5], f); s[6] = ADD(s[6], g); s[7] = ADD(s[7], h);
}

static inline uint64_t be64(const uint8_t *p) {
  uint64_t v;
  memcpy(&v, p, 8);
  return __builtin_bswap64(v);
}

// PBKDF2-HMAC-SHA512 for 4 64-byte passwords, 16-byte salt, first 64-byte block only.
// Every HMAC is exactly 2 compressions thanks to the precomputed ipad/opad states.
static void pbkdf2_4(const uint8_t pw[4][64], const char *salt, uint32_t iters, uint64_t out[4][8]) {
  v4 ib[16], ob[16], ist[8], ost[8], st[8], u[8], t[8], blk[16];
  for (int j = 0; j < 16; j++) {
    uint64_t l[4];
    for (int k = 0; k < 4; k++) l[k] = j < 8 ? be64(pw[k] + 8 * j) : 0;
    v4 key = _mm256_set_epi64x(l[3], l[2], l[1], l[0]);
    ib[j] = XOR(key, SET1(0x3636363636363636));
    ob[j] = XOR(key, SET1(0x5c5c5c5c5c5c5c5c));
  }
  for (int j = 0; j < 8; j++) ist[j] = ost[j] = SET1(IV[j]);
  compress4(ist, ib);
  compress4(ost, ob);

  // U1 = HMAC(pw, salt || INT(1)): 20 bytes after the key block
  blk[0] = SET1(be64((const uint8_t *)salt));
  blk[1] = SET1(be64((const uint8_t *)salt + 8));
  blk[2] = SET1(0x0000000180000000);
  for (int j = 3; j < 15; j++) blk[j] = SET1(0);
  blk[15] = SET1((128 + 20) * 8);
  memcpy(st, ist, sizeof st);
  compress4(st, blk);

  // from here every block is a 64-byte digest after the key block
  for (int j = 0; j < 8; j++) blk[j] = st[j];
  blk[8] = SET1(0x8000000000000000);
  for (int j = 9; j < 15; j++) blk[j] = SET1(0);
  blk[15] = SET1((128 + 64) * 8);
  memcpy(st, ost, sizeof st);
  compress4(st, blk);
  for (int j = 0; j < 8; j++) u[j] = t[j] = st[j];

  for (uint32_t i = 1; i < iters; i++) {
    for (int j = 0; j < 8; j++) blk[j] = u[j];
    memcpy(st, ist, sizeof st);
    compress4(st, blk);
    for (int j = 0; j < 8; j++) blk[j] = st[j];
    memcpy(st, ost, sizeof st);
    compress4(st, blk);
    for (int j = 0; j < 8; j++) {
      u[j] = st[j];
      t[j] = XOR(t[j], st[j]);
    }
  }
  for (int j = 0; j < 8; j++) {
    uint64_t l[4];
    _mm256_storeu_si256((v4 *)l, t[j]);
    for (int k = 0; k < 4; k++) out[k][j] = l[k];
  }
}

// ---------- TON wallets (see lib/ton.mjs WALLETS for the cell layouts) ----------

enum { DATA_V3, DATA_V4, DATA_V5 };
static const struct {
  const char *name;
  uint8_t code_hash[32];
  uint8_t code_depth;
  int data;
} WALLETS[4] = {
  {"v3R1", {0xb6, 0x10, 0x41, 0xa5, 0x8a, 0x79, 0x80, 0xb9, 0x46, 0xe8, 0xfb, 0x9e, 0x19, 0x8e, 0x3c, 0x90,
            0x4d, 0x24, 0x79, 0x9f, 0xfa, 0x36, 0x57, 0x4e, 0xa4, 0x25, 0x1c, 0x41, 0xa5, 0x66, 0xf5, 0x81}, 0, DATA_V3},
  {"v3R2", {0x84, 0xda, 0xfa, 0x44, 0x9f, 0x98, 0xa6, 0x98, 0x77, 0x89, 0xba, 0x23, 0x23, 0x58, 0x07, 0x2b,
            0xc0, 0xf7, 0x6d, 0xc4, 0x52, 0x40, 0x02, 0xa5, 0xd0, 0x91, 0x8b, 0x9a, 0x75, 0xd2, 0xd5, 0x99}, 0, DATA_V3},
  {"v4R2", {0xfe, 0xb5, 0xff, 0x68, 0x20, 0xe2, 0xff, 0x0d, 0x94, 0x83, 0xe7, 0xe0, 0xd6, 0x2c, 0x81, 0x7d,
            0x84, 0x67, 0x89, 0xfb, 0x4a, 0xe5, 0x80, 0xc8, 0x78, 0x86, 0x6d, 0x95, 0x9d, 0xab, 0xd5, 0xc0}, 7, DATA_V4},
  {"W5",   {0x20, 0x83, 0x4b, 0x7b, 0x72, 0xb1, 0x12, 0x14, 0x7e, 0x1b, 0x2f, 0xb4, 0x57, 0xb8, 0x4e, 0x74,
            0xd1, 0xa3, 0x0f, 0x04, 0xf7, 0x37, 0xd4, 0xf6, 0x2a, 0x66, 0x8e, 0x95, 0x52, 0xd2, 0xb7, 0x2f}, 6, DATA_V5},
};
#define WALLET_ID 698983191u
#define WALLET_ID_V5 0x7fffff11u
#define CHECK_ITERS 390 // max(1, floor(100000 / 256)), tonlib is_basic_seed
#define SEED_ITERS 100000

typedef struct {
  uint16_t idx[24];
  uint8_t entropy[64];
} cand_t;

static void draw(cand_t *c, uint8_t *pool, size_t *pool_pos) {
  if (*pool_pos + 33 > 33 * 256) {
    for (size_t got = 0; got < 33 * 256;) {
      ssize_t r = getrandom(pool + got, 33 * 256 - got, 0);
      if (r > 0) got += (size_t)r;
    }
    *pool_pos = 0;
  }
  uint8_t buf[36] = {0};
  memcpy(buf, pool + *pool_pos, 33);
  *pool_pos += 33;
  char phrase[24 * 9];
  size_t len = 0;
  for (int i = 0; i < 24; i++) {
    int bit = i * 11, byte = bit >> 3, shift = bit & 7;
    uint32_t v = ((uint32_t)buf[byte] << 16) | ((uint32_t)buf[byte + 1] << 8) | buf[byte + 2];
    c->idx[i] = (v >> (13 - shift)) & 2047;
    const char *w = WORDLIST[c->idx[i]];
    if (i) phrase[len++] = ' ';
    size_t wl = strlen(w);
    memcpy(phrase + len, w, wl);
    len += wl;
  }
  unsigned int outlen = 64;
  HMAC(EVP_sha512(), phrase, (int)len, (const uint8_t *)"", 0, c->entropy, &outlen);
}

static uint16_t crc16(const uint8_t *p, int n) {
  uint32_t crc = 0;
  for (int i = 0; i < n; i++) {
    crc ^= (uint32_t)p[i] << 8;
    for (int b = 0; b < 8; b++) crc = (crc & 0x8000 ? (crc << 1) ^ 0x1021 : crc << 1) & 0xffff;
  }
  return (uint16_t)crc;
}

static void friendly(const uint8_t hash[32], int bounceable, char out[49]) {
  static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  uint8_t b[36];
  b[0] = bounceable ? 0x11 : 0x51;
  b[1] = 0x00;
  memcpy(b + 2, hash, 32);
  uint16_t crc = crc16(b, 34);
  b[34] = crc >> 8;
  b[35] = crc & 0xff;
  for (int i = 0, o = 0; i < 36; i += 3) {
    uint32_t v = ((uint32_t)b[i] << 16) | ((uint32_t)b[i + 1] << 8) | b[i + 2];
    out[o++] = B64[v >> 18];
    out[o++] = B64[(v >> 12) & 63];
    out[o++] = B64[(v >> 6) & 63];
    out[o++] = B64[v & 63];
  }
  out[48] = 0;
}

static void public_key(const uint8_t seed[32], uint8_t pub[32]) {
  size_t publen = 32;
  EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
  EVP_PKEY_get_raw_public_key(pk, pub, &publen);
  EVP_PKEY_free(pk);
}

static void address_hash(int w, const uint8_t pub[32], uint8_t hash[32]) {
  uint8_t body[40] = {0}, data[43];
  uint32_t id = WALLETS[w].data == DATA_V5 ? WALLET_ID_V5 : WALLET_ID;
  body[4] = id >> 24; body[5] = (id >> 16) & 0xff; body[6] = (id >> 8) & 0xff; body[7] = id & 0xff;
  memcpy(body + 8, pub, 32);
  size_t len;
  data[0] = 0x00;
  if (WALLETS[w].data == DATA_V3) { // 320 bits
    data[1] = 80;
    memcpy(data + 2, body, 40);
    len = 42;
  } else if (WALLETS[w].data == DATA_V4) { // 321 bits: + empty plugins dict
    data[1] = 81;
    memcpy(data + 2, body, 40);
    data[42] = 0x40;
    len = 43;
  } else { // 322 bits: signature-allowed bit first, + empty extensions dict
    data[1] = 81;
    data[2] = 0x80 | (body[0] >> 1);
    for (int i = 1; i < 40; i++) data[2 + i] = (uint8_t)((body[i - 1] << 7) | (body[i] >> 1));
    data[42] = (uint8_t)(((body[39] & 1) << 7) | 0x20);
    len = 43;
  }
  uint8_t init[71] = {0x02, 0x01, 0x34, 0x00, WALLETS[w].code_depth, 0x00, 0x00};
  memcpy(init + 7, WALLETS[w].code_hash, 32);
  SHA256(data, len, init + 39);
  SHA256(init, sizeof init, hash);
}

// ---------- search ----------

static int n_threads, case_sensitive;
static long emit_left = -1; // >= 0 in emit mode
static char prefix[64], suffix[64];
static size_t prefix_len, suffix_len;
static atomic_ullong draws, valid;
static pthread_mutex_t out_lock = PTHREAD_MUTEX_INITIALIZER;

static void print_words(const cand_t *c) {
  for (int i = 0; i < 24; i++) printf(" %s", WORDLIST[c->idx[i]]);
  printf("\n");
}

static int matches(const char addr[49]) {
  char a[49];
  for (int i = 0; i < 49; i++) a[i] = case_sensitive ? addr[i] : (char)tolower((unsigned char)addr[i]);
  if (prefix_len && memcmp(a + 2, prefix, prefix_len)) return 0;
  if (suffix_len && memcmp(a + 48 - suffix_len, suffix, suffix_len)) return 0;
  return 1;
}

static void check_wallets(const cand_t c[4]) {
  uint8_t pw[4][64];
  uint64_t out[4][8];
  for (int k = 0; k < 4; k++) memcpy(pw[k], c[k].entropy, 64);
  pbkdf2_4(pw, "TON default seed", SEED_ITERS, out);
  atomic_fetch_add(&valid, 4);
  for (int k = 0; k < 4; k++) {
    uint8_t seed[32], hash[32];
    for (int j = 0; j < 4; j++) {
      uint64_t v = __builtin_bswap64(out[k][j]);
      memcpy(seed + 8 * j, &v, 8);
    }
    uint8_t pub[32];
    public_key(seed, pub);
    char addr[4][49];
    for (int w = 0; w < 4; w++) {
      address_hash(w, pub, hash);
      friendly(hash, 0, addr[w]);
      if (emit_left < 0 && matches(addr[w])) {
        pthread_mutex_lock(&out_lock);
        char bounce[49];
        friendly(hash, 1, bounce);
        printf("found %llu %llu %s %s %s", (unsigned long long)atomic_load(&draws),
               (unsigned long long)atomic_load(&valid), WALLETS[w].name, addr[w], bounce);
        print_words(&c[k]);
        fflush(stdout);
        _exit(0);
      }
    }
    if (emit_left >= 0) {
      pthread_mutex_lock(&out_lock);
      if (emit_left == 0) _exit(0);
      emit_left--;
      printf("valid %s %s %s %s", addr[0], addr[1], addr[2], addr[3]);
      print_words(&c[k]);
      fflush(stdout);
      pthread_mutex_unlock(&out_lock);
    }
  }
}

static void *worker(void *arg) {
  (void)arg;
  static _Thread_local uint8_t pool[33 * 256];
  size_t pool_pos = sizeof pool;
  cand_t batch[4], ready[8];
  int n_ready = 0;
  uint8_t pw[4][64];
  uint64_t out[4][8];
  for (;;) {
    for (int k = 0; k < 4; k++) {
      draw(&batch[k], pool, &pool_pos);
      memcpy(pw[k], batch[k].entropy, 64);
    }
    pbkdf2_4(pw, "TON seed version", CHECK_ITERS, out);
    atomic_fetch_add(&draws, 4);
    for (int k = 0; k < 4; k++)
      if ((out[k][0] >> 56) == 0) ready[n_ready++] = batch[k];
    if (n_ready >= 4) {
      check_wallets(ready);
      n_ready -= 4;
      memmove(ready, ready + 4, n_ready * sizeof *ready);
    }
  }
  return NULL;
}

static double now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

int main(int argc, char **argv) {
  if (argc == 3 && !strcmp(argv[1], "emit")) {
    n_threads = 1;
    emit_left = atol(argv[2]);
  } else if (argc == 5) {
    n_threads = atoi(argv[1]);
    case_sensitive = atoi(argv[4]);
    prefix_len = strlen(argv[2]);
    suffix_len = strlen(argv[3]);
    if (n_threads < 1 || prefix_len > 46 || suffix_len > 46) return 2;
    for (size_t i = 0; i < prefix_len; i++)
      prefix[i] = case_sensitive ? argv[2][i] : (char)tolower((unsigned char)argv[2][i]);
    for (size_t i = 0; i < suffix_len; i++)
      suffix[i] = case_sensitive ? argv[3][i] : (char)tolower((unsigned char)argv[3][i]);
  } else {
    fprintf(stderr, "usage: ton-vanity-native <threads> <prefix> <suffix> <case-sensitive 0|1>\n");
    return 2;
  }
  for (int i = 0; i < n_threads; i++) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
  }
  double last = now_ms();
  for (;;) {
    sleep(1);
    double t = now_ms();
    if (emit_left >= 0) continue;
    pthread_mutex_lock(&out_lock);
    printf("progress %llu %llu %.0f\n", (unsigned long long)atomic_exchange(&draws, 0),
           (unsigned long long)atomic_exchange(&valid, 0), t - last);
    fflush(stdout);
    pthread_mutex_unlock(&out_lock);
    last = t;
  }
}
