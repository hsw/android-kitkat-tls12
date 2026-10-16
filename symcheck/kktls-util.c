/* SPDX-License-Identifier: Apache-2.0 */
/*
 * kktls-util: the file operations the kktls installer needs where the recovery or a stock 4.4 shell lacks a tool.
 *
 *   kktls-util setcon CONTEXT PATH...
 *        set the SELinux label (the security.selinux xattr, NUL-terminated as chcon writes it) of each PATH without
 *        following a symlink; exit 0 all set, 1 at least one failed (reason on stderr), 2 usage
 *   kktls-util has-entry ZIP NAME
 *        exit 0 when the central directory of ZIP lists an entry named exactly NAME, 1 when it does not,
 *        2 usage or ZIP is not a readable zip (no end-of-central-directory record, a truncated directory, zip64)
 *   kktls-util sha256 FILE
 *        print the SHA-256 of FILE as 64 lowercase hex digits and a newline; exit 0, 2 usage or FILE not readable
 *
 * has-entry is the installer's dex check (does a jar/apk next to an .odex still carry classes.dex?); busybox unzip is
 * not there on a stock device shell. The file is parsed byte-wise (no struct casts), like kktls-symcheck.
 * sha256 is the digest of the backup manifests: a recovery's busybox may lack sha256sum (and md5sum), so the installer
 * never depends on it. FIPS 180-4, the file streamed through a fixed buffer.
 * Built static per ABI by the Android.mk next to this file.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>

#define MAX_FILE (512u * 1024u * 1024u)
#define EOCD_SIZE 22u
#define EOCD_SEARCH (EOCD_SIZE + 65535u)
#define CDH_SIZE 46u

static uint32_t le16(const unsigned char *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8; }
static uint32_t le32(const unsigned char *p) {
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int usage(void) {
  fprintf(stderr, "usage: kktls-util setcon CONTEXT PATH...\n       kktls-util has-entry ZIP NAME\n"
                  "       kktls-util sha256 FILE\n");
  return 2;
}

static int do_setcon(int argc, char **argv) {
  if (argc < 4 || argv[2][0] == '\0') return usage();
  const char *ctx = argv[2];
  int rc = 0;
  for (int i = 3; i < argc; i++) {
    if (lsetxattr(argv[i], "security.selinux", ctx, strlen(ctx) + 1, 0) != 0) {
      fprintf(stderr, "kktls-util: setcon %s %s: %s\n", ctx, argv[i], strerror(errno));
      rc = 1;
    }
  }
  return rc;
}

/* reads the whole file (jars and apks of /system are well below MAX_FILE); NULL on error */
static unsigned char *slurp(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  if (!f) { fprintf(stderr, "kktls-util: %s: %s\n", path, strerror(errno)); return NULL; }
  size_t cap = 1u << 16, n = 0;
  unsigned char *buf = malloc(cap);
  while (buf) {
    if (n == cap) {
      if (cap >= MAX_FILE) { fprintf(stderr, "kktls-util: %s: too large\n", path); free(buf); buf = NULL; break; }
      unsigned char *nb = realloc(buf, cap * 2);
      if (!nb) { free(buf); buf = NULL; break; }
      buf = nb; cap *= 2;
    }
    size_t r = fread(buf + n, 1, cap - n, f);
    n += r;
    if (r == 0) {
      if (ferror(f)) { fprintf(stderr, "kktls-util: %s: read error\n", path); free(buf); buf = NULL; }
      break;
    }
  }
  fclose(f);
  *len = n;
  return buf;
}

static int do_has_entry(int argc, char **argv) {
  if (argc != 4 || argv[3][0] == '\0') return usage();
  const char *zip = argv[2], *name = argv[3];
  size_t len, nlen = strlen(name);
  unsigned char *b = slurp(zip, &len);
  if (!b) return 2;
  int rc = 2;
  /* the last end-of-central-directory signature whose comment length reaches exactly the end of the file */
  size_t eocd = (size_t)-1;
  if (len >= EOCD_SIZE) {
    size_t lo = len > EOCD_SEARCH ? len - EOCD_SEARCH : 0;
    for (size_t i = len - EOCD_SIZE + 1; i-- > lo;) {
      if (le32(b + i) == 0x06054b50u && i + EOCD_SIZE + le16(b + i + 20) == len) { eocd = i; break; }
    }
  }
  if (eocd == (size_t)-1) { fprintf(stderr, "kktls-util: %s: not a zip (no end of central directory)\n", zip); goto out; }
  uint32_t count = le16(b + eocd + 10), size = le32(b + eocd + 12), off = le32(b + eocd + 16);
  if (count == 0xffffu || size == 0xffffffffu || off == 0xffffffffu) {
    fprintf(stderr, "kktls-util: %s: zip64 is not supported\n", zip); goto out;
  }
  if (off > eocd || size > eocd - off) { fprintf(stderr, "kktls-util: %s: central directory out of range\n", zip); goto out; }
  size_t p = off, end = (size_t)off + size;
  for (uint32_t i = 0; i < count; i++) {
    if (end - p < CDH_SIZE || le32(b + p) != 0x02014b50u) {
      fprintf(stderr, "kktls-util: %s: bad central directory entry %u\n", zip, (unsigned)i); goto out;
    }
    size_t fl = le16(b + p + 28), xl = le16(b + p + 30), cl = le16(b + p + 32);
    if (end - p - CDH_SIZE < fl + xl + cl) {
      fprintf(stderr, "kktls-util: %s: truncated central directory entry %u\n", zip, (unsigned)i); goto out;
    }
    if (fl == nlen && memcmp(b + p + CDH_SIZE, name, nlen) == 0) { rc = 0; goto out; }
    p += CDH_SIZE + fl + xl + cl;
  }
  rc = 1;
out:
  free(b);
  return rc;
}

/* SHA-256 (FIPS 180-4) */
static const uint32_t K256[64] = {
  0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
  0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
  0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
  0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
  0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
  0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
  0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
  0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

struct sha256 {
  uint32_t h[8];
  uint64_t len;           /* bytes fed so far */
  unsigned char blk[64];
  size_t n;               /* bytes waiting in blk */
};

static uint32_t ror(uint32_t x, unsigned r) { return x >> r | x << (32 - r); }

static void sha256_block(uint32_t h[8], const unsigned char *p) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++) w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 |
                                      (uint32_t)p[4 * i + 2] << 8 | (uint32_t)p[4 * i + 3];
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ w[i - 15] >> 3;
    uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ w[i - 2] >> 10;
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
  for (int i = 0; i < 64; i++) {
    uint32_t t1 = k + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
    uint32_t t2 = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    k = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += k;
}

static void sha256_init(struct sha256 *s) {
  static const uint32_t iv[8] = { 0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                  0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u };
  memcpy(s->h, iv, sizeof iv);
  s->len = 0;
  s->n = 0;
}

static void sha256_update(struct sha256 *s, const unsigned char *p, size_t len) {
  s->len += len;
  while (len > 0) {
    size_t take = 64 - s->n < len ? 64 - s->n : len;
    memcpy(s->blk + s->n, p, take);
    s->n += take; p += take; len -= take;
    if (s->n == 64) { sha256_block(s->h, s->blk); s->n = 0; }
  }
}

static void sha256_final(struct sha256 *s, unsigned char out[32]) {
  uint64_t bits = s->len * 8;
  s->blk[s->n++] = 0x80;
  if (s->n > 56) {
    memset(s->blk + s->n, 0, 64 - s->n);
    sha256_block(s->h, s->blk);
    s->n = 0;
  }
  memset(s->blk + s->n, 0, 56 - s->n);
  for (int i = 0; i < 8; i++) s->blk[56 + i] = (unsigned char)(bits >> (56 - 8 * i));
  sha256_block(s->h, s->blk);
  for (int i = 0; i < 8; i++) {
    out[4 * i] = (unsigned char)(s->h[i] >> 24); out[4 * i + 1] = (unsigned char)(s->h[i] >> 16);
    out[4 * i + 2] = (unsigned char)(s->h[i] >> 8); out[4 * i + 3] = (unsigned char)s->h[i];
  }
}

static int do_sha256(int argc, char **argv) {
  if (argc != 3 || argv[2][0] == '\0') return usage();
  const char *path = argv[2];
  FILE *f = fopen(path, "rb");
  if (!f) { fprintf(stderr, "kktls-util: %s: %s\n", path, strerror(errno)); return 2; }
  struct sha256 s;
  unsigned char buf[16384], d[32];
  size_t r;
  sha256_init(&s);
  while ((r = fread(buf, 1, sizeof buf, f)) > 0) sha256_update(&s, buf, r);
  int err = ferror(f);
  fclose(f);
  if (err) { fprintf(stderr, "kktls-util: %s: read error\n", path); return 2; }
  sha256_final(&s, d);
  for (int i = 0; i < 32; i++) printf("%02x", d[i]);
  printf("\n");
  return fflush(stdout) == 0 && !ferror(stdout) ? 0 : 2;
}

int main(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "setcon") == 0) return do_setcon(argc, argv);
  if (argc >= 2 && strcmp(argv[1], "has-entry") == 0) return do_has_entry(argc, argv);
  if (argc >= 2 && strcmp(argv[1], "sha256") == 0) return do_sha256(argc, argv);
  return usage();
}
