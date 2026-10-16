/* SPDX-License-Identifier: Apache-2.0 */
/*
 * CVE-2023-3446 - DH_check() does unbounded work on an over-large modulus.
 * DH_check() runs BN_is_prime_ex() on dh->p (and on (p-1)/2) with no size
 * cap, so a DH parameter set carrying a huge modulus - trivially present in
 * attacker-supplied DH params / an X9.42 DH key - makes the primality test
 * grind for an unbounded time (DoS). Fix: 8780a89654 (crypto/dh/dh_check.c +
 * dh.h) caps BN_num_bits(dh->p) at OPENSSL_DH_CHECK_MAX_MODULUS_BITS (32768)
 * and returns 0 with DH_R_MODULUS_TOO_LARGE before any prime test.
 *
 * attack : p = 2^40000 + 1 (40001 bits: > the 32768 cap, odd, and survives
 *          small-prime trial division so BN_is_prime_ex reaches the expensive
 *          Miller-Rabin modexp), g = 2. On the unfixed lib DH_check grinds in
 *          BN_is_prime_ex; on the fixed lib it refuses the modulus at once.
 * control: p = 23 (a real prime, well under the cap), g = 2 -> returns at once
 *          on both the fixed and the unfixed lib.
 *
 * Verdict (hang class): a fixed lib returns 0 with
 * DH_R_MODULUS_TOO_LARGE and prints KKTLS_CVE_RESULT=rejected; an unfixed lib
 * either finishes the primality work (KKTLS_CVE_RESULT=accepted) or never
 * returns within the expect timeout (rc 124, a safety bound). The control
 * must print accepted on every lib.
 */
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include "../cve_common.h"

int main(int argc, char **argv)
{
    int ctl = cve_is_control(argc, argv);
    DH *dh = DH_new();
    int codes = 0, ret;

    if (dh == NULL)
        return 2;
    dh->p = BN_new();
    dh->g = BN_new();
    if (dh->p == NULL || dh->g == NULL)
        return 2;
    BN_set_word(dh->g, DH_GENERATOR_2);
    if (ctl) {
        BN_set_word(dh->p, 23);
    } else {
        BN_set_bit(dh->p, 40000);   /* p = 2^40000 ... */
        BN_set_bit(dh->p, 0);       /* ... + 1 (odd) */
    }

    cve_call("DH_check");
    ret = DH_check(dh, &codes);
    cve_reached("DH_check");
    printf("DH_check ret=%d codes=0x%x\n", ret, codes);
    if (ret == 0
        && ERR_GET_REASON(ERR_peek_last_error()) == DH_R_MODULUS_TOO_LARGE)
        cve_result("rejected", "DH_R_MODULUS_TOO_LARGE");
    else
        cve_result("accepted", ctl ? "small-p" : "did-prime-check");

    DH_free(dh);
    return 0;
}
