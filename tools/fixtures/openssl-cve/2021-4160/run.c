/* SPDX-License-Identifier: Apache-2.0 */
/*
 * CVE-2021-4160 - carry-propagation bug in the 32-bit MIPS bn_sqr_comba4/8
 * assembly (crypto/bn/asm/mips.pl). The 2*a[0]*a[1] cross term dropped a
 * carry out of the doubling add, so bn_sqr_comba produced a wrong square for
 * some inputs on mips/mipsel o32 builds, which in turn makes
 * BN_mod_exp_mont_consttime return a wrong modular exponentiation. Fix:
 * upstream e9e726506c (carried in this port as commit 6e92ffd, +4 lines in
 * mips.pl, regenerated into bn-mips.S by the import). MIPS asm only; every
 * other arch and the no-asm build are unaffected.
 *
 * Known-answer test (kat class), not an exploit: a benign numeric vector that
 * the buggy asm squares incorrectly and the fixed asm squares correctly.
 *
 * Method (known-answer test). The vector
 * is upstream's own regression input (commit e9e726506c, carried verbatim in
 * the port's crypto/bn/bntest.c by commit 6e92ffd). Upstream's test is only
 * differential (two routines must agree, no expected value is published);
 * here base^exp mod m is computed two ways and EACH result is compared with a
 * hard-coded expected value (cve_kat_hex below):
 *   d = BN_mod_exp_mont_consttime(e, p, m)   - the constant-time Montgomery
 *       windowed exponentiation. On 32-bit MIPS bn_mul_mont (mips-mont.pl)
 *       declines num >= 17 words ("slt $at,$num,17"), so for this 2048-bit
 *       (64-word) operand the Montgomery squarings fall back to BN_sqr ->
 *       bn_sqr_comba8 -- the buggy asm -- on Montgomery-form residues.
 *   a = BN_mod_exp_simple(e, p, m)           - the plain-residue exponentiation.
 *       It ALSO squares through BN_sqr -> bn_sqr_comba8 (BN_mod_mul takes its
 *       a==b BN_sqr branch), on plain residues with a different schedule.
 * Upstream's vector trips the dropped carry in at least one of the two
 * sequences. Verdict: both d and a equal the expected value ->
 * KKTLS_CVE_RESULT=correct; either differs -> KKTLS_CVE_RESULT=wrong (the detail
 * names which path: consttime:differ, simple:differ, both:differ).
 *
 * Expected value: computed 2026-10-13 with Python's arbitrary-precision
 * pow(e, p, m) (independent of OpenSSL) and cross-checked against the x86_64
 * no-asm libcrypto of u-android c32541c (both paths equal it there).
 *
 * attack : the upstream e9e726506c regression vector (2048-bit e/p/m).
 * control: a tiny benign vector (1-word operands, never reaches comba4/8):
 *          2^10 mod 1000003 = 0x400 on both paths and both libraries ->
 *          correct, as the kat control contract requires.
 *
 * libcrypto only (no libssl); runs only under --mips --asm (expect:
 * arches=mips, needs_asm=yes), SKIP everywhere else.
 */
#include <openssl/bn.h>
#include <openssl/err.h>
#include <stdio.h>
#include "../cve_common.h"

/*
 * Upstream CVE-2021-4160 regression vector (commit e9e726506c), carried
 * verbatim into this port's crypto/bn/bntest.c by commit 6e92ffd. base = e,
 * exponent = p, modulus = m; the hex is concatenated for BN_hex2bn exactly as
 * in the port's test.
 */
static const char cve_ehex[] =
    "95564994a96c45954227b845a1e99cb939d5a1da99ee91acc962396ae999a9ee"
    "38603790448f2f7694c242a875f0cad0aae658eba085f312d2febbbd128dd2b5"
    "8f7d1149f03724215d704344d0d62c587ae3c5939cba4b9b5f3dc5e8e911ef9a"
    "5ce1a5a749a4989d0d8368f6e1f8cdf3a362a6c97fb02047ff152b480a4ad985"
    "2d45efdf0770542992afca6a0590d52930434bba96017afbc9f99e112950a8b1"
    "a359473ec376f329bdae6a19f503be6d4be7393c4e43468831234e27e3838680"
    "b949390d2e416a3f9759e5349ab4c253f6f29f819a6fe4cbfd27ada34903300e"
    "da021f62839f5878a36f1bc3085375b00fd5fa3e68d316c0fdace87a97558465";
static const char cve_phex[] =
    "f95dc0f980fbd22e90caa5a387cc4a369f3f830d50dd321c40db8c09a7e1a241"
    "a536e096622d3280c0c1ba849c1f4a79bf490f60006d081e8cf69960189f0d31"
    "2cd9e17073a3fba7881b21474a13b334116cb2f5dbf3189a6de3515d0840f053"
    "c776d3982d391b6d04d642dda5cc6d1640174c09875addb70595658f89efb439"
    "dc6fbd55f903aadd307982d3f659207f265e1ec6271b274521b7a5e28e8fd7a5"
    "5df089292820477802a43cf5b6b94e999e8c9944ddebb0d0e95a60f88cb7e813"
    "ba110d20e1024774107dd02949031864923b3cb8c3f7250d6d1287b0a40db6a4"
    "7bd5a469518eb65aa207ddc47d8c6e5fc8e0c105be8fc1d4b57b2e27540471d5";
static const char cve_mhex[] =
    "fef15d5ce4625f1bccfbba49fc8439c72bf8202af039a2259678941b60bb4a8f"
    "2987e965d58fd8cf86a856674d519763d0e1211cc9f8596971050d56d9b35db3"
    "785866cfbca17cfdbed6060be3629d894f924a89fdc1efc624f80d41a22f1900"
    "9503fcc3824ef62ccb9208430c26f2d8ceb2c63488ec4c07437aa4c96c43dd8b"
    "9289ed00a712ff66ee195dc71f5e4ead02172b63c543d69baf495f5fd63ba7bc"
    "c633bd309c016e37736da92129d0b053d4ab28d21ad7d8b6fab2a8bbdc8ee647"
    "d2fbcf2cf426cf892e6f5639e0252993965dfb73ccd277407014ea784aaa280c"
    "b7b03972bc8b0baa72360bdb44b82415b86b2f260f877791cd33ba8f2d65229b";

/* Known answer: e^p mod m for the vector above (2048 bits; Python pow,
 * cross-checked on the no-asm build - see the header). */
static const char cve_kat_hex[] =
    "ccb051a34f9e26e381e50445632cbbd4abe56bc912020f3edd2db144aedb4700"
    "95c4c33e3342d1dc4bb4056ba3078366af4cee507e85bb1b2e499ef25a933810"
    "f14faa8b1a9ce5e8d58f2789e27c887a4ff87fa59ff682727a3912a99aae6db8"
    "b3b8947d76c8454cffc6fb3f2422dca106c3845b0db68a06e5e9d7b90e552506"
    "579d812e7d96bfc6324feec90ea0800463346148f120e7caf403788539f5d87e"
    "e45aa5b313c340e0a323029f3a0bdb675510aefec171c01e2a94960cd507e461"
    "214028c86ed4e9fce31e7dbdf1a75fd6f973e2aed4a039e53a60a7aa62be8ee1"
    "f80a113833ab402d07e17151021cec29fa5b2e628ef9f2d7aa4bc86b6eec8faf";

/* Benign control: 2^10 mod 1000003 = 1024. One-word operands, so the fixed-
 * size comba squaring (bn_sqr_comba4/8) is never reached; correct on both. */
static const char ctl_ehex[] = "2";
static const char ctl_phex[] = "a";
static const char ctl_mhex[] = "f4243"; /* 1000003, odd */
static const char ctl_kat_hex[] = "400";  /* 1024 */

int main(int argc, char **argv)
{
    int ctl = cve_is_control(argc, argv);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *e = BN_new(), *p = BN_new(), *m = BN_new();
    BIGNUM *a = BN_new(), *d = BN_new(), *want = BN_new();
    const char *eh, *ph, *mh, *kh, *tag;
    int ok, d_ok, a_ok;

    if (ctx == NULL || !e || !p || !m || !a || !d || !want) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }

    if (ctl) {
        eh = ctl_ehex; ph = ctl_phex; mh = ctl_mhex; kh = ctl_kat_hex;
        tag = "control";
    } else {
        eh = cve_ehex; ph = cve_phex; mh = cve_mhex; kh = cve_kat_hex;
        tag = "cve-2021-4160";
    }

    if (!BN_hex2bn(&e, eh) || !BN_hex2bn(&p, ph) || !BN_hex2bn(&m, mh)
            || !BN_hex2bn(&want, kh)) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "BN_hex2bn failed\n");
        return 1;
    }

    /* The computation under test: the two exponentiations and the compare. */
    cve_call("BN_mod_exp_mont_consttime");
    ok = BN_mod_exp_mont_consttime(d, e, p, m, ctx, NULL)
         && BN_mod_exp_simple(a, e, p, m, ctx);
    cve_reached("BN_mod_exp_mont_consttime");

    if (!ok) {
        /* a setup/compute failure must be an ERROR, never a false verdict */
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "mod_exp computation failed (%s)\n", tag);
        return 1;
    }

    d_ok = (BN_cmp(d, want) == 0);
    a_ok = (BN_cmp(a, want) == 0);
    printf("known answer: consttime %s, simple %s (%s)\n",
           d_ok ? "equal" : "DIFFER", a_ok ? "equal" : "DIFFER", tag);
    if (d_ok && a_ok)
        cve_result("correct", "kat:both-equal");
    else
        cve_result("wrong", !d_ok && !a_ok ? "kat:both:differ"
                            : !d_ok ? "kat:consttime:differ"
                                    : "kat:simple:differ");

    BN_free(e); BN_free(p); BN_free(m); BN_free(a); BN_free(d); BN_free(want);
    BN_CTX_free(ctx);
    return 0;
}
