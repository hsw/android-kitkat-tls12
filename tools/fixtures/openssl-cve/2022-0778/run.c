/* SPDX-License-Identifier: Apache-2.0 */
/*
 * CVE-2022-0778 - infinite loop in BN_mod_sqrt() for a non-prime modulus.
 * A TLS server certificate with crafted explicit elliptic-curve parameters
 * reaches BN_mod_sqrt (computing a point's y from x) before the certificate
 * is verified; a composite field prime makes the Tonelli-Shanks loop never
 * terminate. Fix: 3118eb6493 (crypto/bn/bn_sqrt.c).
 *
 * attack : A/P from the OpenSSL regression vector that loops on the unfixed
 *          code (test/recipes/10-test_bn_data/bnmod.txt, commit 3ef5c3034e:
 *          "This one triggers an infinite loop with unfixed implementation").
 * control: sqrt(4) mod 7 == 2, a real prime, returns at once.
 *
 * Verdict (hang class): the unfixed loop never ends, so the
 * vulnerable verdict is the harness safety bound (timeout with
 * KKTLS_CVE_CALL only). A fixed lib returns NULL with BN_R_NOT_A_SQUARE and
 * prints KKTLS_CVE_RESULT=rejected; any other return is "unexpected" (ERROR).
 */
#include <openssl/bn.h>
#include <openssl/err.h>
#include "../cve_common.h"

int main(int argc, char **argv)
{
    int ctl = cve_is_control(argc, argv);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *a = NULL, *p = NULL, *r;

    if (ctl) {
        BN_dec2bn(&a, "4");
        BN_dec2bn(&p, "7");
    } else {
        /* non-prime p; unfixed BN_mod_sqrt never returns */
        BN_hex2bn(&a, "20a7ee");
        BN_hex2bn(&p, "460201");
    }

    cve_call("BN_mod_sqrt");
    r = BN_mod_sqrt(NULL, a, p, ctx);
    cve_reached("BN_mod_sqrt");
    /* Reached only when BN_mod_sqrt returns (control, or a patched lib). */
    printf("BN_mod_sqrt returned %s\n", r ? "a value" : "NULL (no square)");
    if (ctl)
        cve_result(r && BN_is_word(r, 2) ? "accepted" : "unexpected", "sqrt(4)mod7");
    else if (r == NULL && ERR_GET_REASON(ERR_peek_last_error()) == BN_R_NOT_A_SQUARE)
        cve_result("rejected", "BN_R_NOT_A_SQUARE");
    else
        cve_result("unexpected", r ? "returned-a-root" : "other-error");
    if (r)
        BN_free(r);
    BN_free(a);
    BN_free(p);
    BN_CTX_free(ctx);
    return 0;
}
