/* SPDX-License-Identifier: Apache-2.0 */
/*
 * CVE-2020-1971 template completion - EDIPartyName tagging (upstream
 * aa0ad2011d, 1.1.1i, ported to u-android with 1ecc76f674 and 41d62636fd).
 *
 * RFC 5280: EDIPartyName ::= SEQUENCE { nameAssigner [0] DirectoryString
 * OPTIONAL, partyName [1] DirectoryString }. DirectoryString is a CHOICE, so
 * both tags are EXPLICIT. 1.0.1u declared them IMPLICIT (and partyName
 * OPTIONAL); its encoder and decoder ignore an implicit tag on a multi-string,
 * so it wrote the strings without the [0]/[1] wrappers and could not read a
 * correct encoding back. The CVE-2020-1971 NULL dereference itself is fixed by
 * the edipartyname_cmp port (f960d81215); this test covers the template part.
 *
 * Known-answer test (kat class), not an exploit: only well-formed values,
 * built through the public API.
 *   attack : two EDIPartyName GENERAL_NAMEs (A: partyName "foo" only;
 *            B: nameAssigner "ab" + partyName "foo"). For each:
 *            1. i2d_GENERAL_NAME must equal the RFC 5280 DER (hard-coded,
 *               derived by hand from the ASN.1 above);
 *            2. d2i_GENERAL_NAME of that DER must succeed, give GEN_EDIPARTY
 *               and the same nameAssigner/partyName as the built value;
 *            3. re-encoding the decoded value must give the same DER.
 *            All hold -> KKTLS_CVE_RESULT=correct; else KKTLS_CVE_RESULT=wrong
 *            with the first failing vector and its failed steps as detail.
 *            Expected on 1.0.1u without aa0ad2011d: step 1 differs (no [1]
 *            wrapper) and step 2 fails (the [1] wrapper is not read) ->
 *            wrong (kat:A:encode:differ+decode:fail).
 *   control: a dNSName GENERAL_NAME (IA5String, implicit [2], unaffected) put
 *            through the same three steps -> correct on both libraries.
 *
 * Fields are compared with ASN1_STRING_cmp, not GENERAL_NAME_cmp: on a library
 * without the 1971 compare fix GENERAL_NAME_cmp of two EDIPartyNames is the
 * bug itself.
 *
 * libcrypto only (no libssl); same verdict on every arch.
 */
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>
#include "../cve_common.h"

/* A: [5] { [1] { UTF8String "foo" } } */
static const unsigned char der_a[] = {
    0xa5, 0x07, 0xa1, 0x05, 0x0c, 0x03, 'f', 'o', 'o'
};

/* B: [5] { [0] { UTF8String "ab" }, [1] { UTF8String "foo" } } */
static const unsigned char der_b[] = {
    0xa5, 0x0d, 0xa0, 0x04, 0x0c, 0x02, 'a', 'b',
    0xa1, 0x05, 0x0c, 0x03, 'f', 'o', 'o'
};

/* control: dNSName [2] IMPLICIT IA5String "example.com" */
static const unsigned char der_ctl[] = {
    0x82, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'
};

static ASN1_STRING *utf8(const char *s)
{
    ASN1_STRING *str = ASN1_STRING_type_new(V_ASN1_UTF8STRING);

    if (str != NULL && !ASN1_STRING_set(str, s, (int)strlen(s))) {
        ASN1_STRING_free(str);
        str = NULL;
    }
    return str;
}

/* EDIPartyName GENERAL_NAME; assigner may be NULL. NULL on setup failure. */
static GENERAL_NAME *make_edi(const char *assigner, const char *party)
{
    GENERAL_NAME *gen = GENERAL_NAME_new();
    EDIPARTYNAME *edi = EDIPARTYNAME_new();

    if (gen == NULL || edi == NULL)
        goto err;
    if (assigner != NULL && (edi->nameAssigner = utf8(assigner)) == NULL)
        goto err;
    if ((edi->partyName = utf8(party)) == NULL)
        goto err;
    GENERAL_NAME_set0_value(gen, GEN_EDIPARTY, edi);
    return gen;
 err:
    EDIPARTYNAME_free(edi);
    GENERAL_NAME_free(gen);
    return NULL;
}

static GENERAL_NAME *make_dns(const char *name)
{
    GENERAL_NAME *gen = GENERAL_NAME_new();
    ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();

    if (gen == NULL || ia5 == NULL
            || !ASN1_STRING_set(ia5, name, (int)strlen(name))) {
        ASN1_IA5STRING_free(ia5);
        GENERAL_NAME_free(gen);
        return NULL;
    }
    GENERAL_NAME_set0_value(gen, GEN_DNS, ia5);
    return gen;
}

/* 0 if both are NULL or both are set and equal. */
static int str_differs(const ASN1_STRING *a, const ASN1_STRING *b)
{
    if (a == NULL || b == NULL)
        return a != b;
    return ASN1_STRING_cmp(a, b) != 0;
}

static int fields_differ(const GENERAL_NAME *a, const GENERAL_NAME *b)
{
    if (a->type != b->type)
        return 1;
    if (a->type == GEN_DNS)
        return str_differs(a->d.dNSName, b->d.dNSName);
    if (a->type != GEN_EDIPARTY)
        return 1;
    return str_differs(a->d.ediPartyName->nameAssigner,
                       b->d.ediPartyName->nameAssigner)
        || str_differs(a->d.ediPartyName->partyName,
                       b->d.ediPartyName->partyName);
}

static int der_equal(const unsigned char *der, int len,
                     const unsigned char *want, size_t wlen)
{
    return len == (int)wlen && memcmp(der, want, wlen) == 0;
}

/*
 * The three steps for one vector. Returns NULL when all hold, else a static
 * detail token naming the vector and the failed steps. The decode step runs
 * even when the encoding differs, so a library that cannot read the RFC 5280
 * DER shows "decode:fail" as well.
 */
static const char *check(const char *name, const GENERAL_NAME *built,
                         const unsigned char *want, size_t wlen)
{
    static char detail[64];
    unsigned char *der = NULL, *der2 = NULL;
    const unsigned char *p;
    GENERAL_NAME *dec = NULL;
    const char *enc = NULL, *step = NULL;
    int len, len2;

    len = i2d_GENERAL_NAME((GENERAL_NAME *)built, &der);
    printf("%s: i2d len %d (want %d)\n", name, len, (int)wlen);
    if (len <= 0 || !der_equal(der, len, want, wlen)) {
        enc = "encode:differ";
    }
    p = want;
    dec = d2i_GENERAL_NAME(NULL, &p, (long)wlen);
    if (dec == NULL || p != want + wlen) {
        ERR_print_errors_fp(stdout);
        step = "decode:fail";
        goto done;
    }
    if (fields_differ(built, dec)) {
        step = "fields:differ";
        goto done;
    }
    len2 = i2d_GENERAL_NAME(dec, &der2);
    if (len2 <= 0 || !der_equal(der2, len2, want, wlen))
        step = "reencode:differ";
 done:
    OPENSSL_free(der);
    OPENSSL_free(der2);
    GENERAL_NAME_free(dec);
    if (enc == NULL && step == NULL)
        return NULL;
    snprintf(detail, sizeof(detail), "kat:%s:%s%s%s", name,
             enc != NULL ? enc : "", enc != NULL && step != NULL ? "+" : "",
             step != NULL ? step : "");
    return detail;
}

int main(int argc, char **argv)
{
    int ctl = cve_is_control(argc, argv);
    GENERAL_NAME *a = NULL, *b = NULL;
    const char *bad = NULL;

    ERR_load_crypto_strings();
    if (ctl) {
        a = make_dns("example.com");
    } else {
        a = make_edi(NULL, "foo");
        b = make_edi("ab", "foo");
    }
    if (a == NULL || (!ctl && b == NULL)) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "GENERAL_NAME setup failed\n");
        return 1;
    }

    /* The computation under test: encode, decode, re-encode. */
    cve_call("i2d_GENERAL_NAME");
    if (ctl) {
        bad = check("dns", a, der_ctl, sizeof(der_ctl));
    } else {
        bad = check("A", a, der_a, sizeof(der_a));
        if (bad == NULL)
            bad = check("B", b, der_b, sizeof(der_b));
    }
    cve_reached("i2d_GENERAL_NAME");

    printf("known answer: %s (%s)\n", bad == NULL ? "all equal" : bad,
           ctl ? "control" : "cve-2020-1971-template");
    if (bad == NULL)
        cve_result("correct", ctl ? "kat:dns:round-trip"
                                  : "kat:edi:rfc5280-der");
    else
        cve_result("wrong", bad);

    GENERAL_NAME_free(a);
    GENERAL_NAME_free(b);
    return 0;
}
