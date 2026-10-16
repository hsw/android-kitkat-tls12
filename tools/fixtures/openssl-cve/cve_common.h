/* SPDX-License-Identifier: Apache-2.0 */
/*
 * cve_common.h - shared helpers for the OpenSSL post-EOL CVE reproducers
 * (harness tools/openssl-cve-test.sh). Each reproducer is a run.c with:
 *
 *   ./run attack     exercise the bug (on a vulnerable libcrypto/libssl it
 *                    hangs, crashes, trips ASan or balloons RSS)
 *   ./run control    the same code path on benign input (always returns 0
 *                    quickly, well under every threshold)
 *
 * The harness classifies attack by failure class (expect: class=...):
 *   hang   -> decided by work done, not by wall clock: the call
 *             returned and run.c printed KKTLS_CVE_RESULT=accepted (the lib
 *             did the unbounded work instead of refusing the input), or the
 *             call never returned within the expect timeout (exit 124, a
 *             safety bound only). A fixed lib prints KKTLS_CVE_RESULT=rejected
 *             with its specific error; the control must print accepted.
 *   crash  -> the process dies from a signal (exit >=128; SEGV/ABRT)
 *   asan   -> stderr carries "AddressSanitizer" (lib + run built with ASan)
 *   mem    -> run prints "MAXRSS_KB=<n>"; n >= expect:rss_kb is the vuln
 *   kat    -> known-answer test ( e.g. a wrong bn-mips.S square
 *             under --mips --asm): run.c prints KKTLS_CVE_RESULT=wrong (vuln)
 *             or KKTLS_CVE_RESULT=correct (fixed; the control must be correct)
 *
 * Markers: every run.c calls cve_call("<fn>")
 * right before the call under test and cve_reached("<fn>") right after it
 * returns. The harness requires KKTLS_CVE_REACHED (and rc 0) for a fixed
 * verdict and a clean control, and KKTLS_CVE_CALL without KKTLS_CVE_REACHED for a
 * hang or crash verdict, so a reproducer that fails or exits early (bad
 * input, setup error) is an ERROR instead of a PASS.
 *
 * No header or source from the AOSP tree is used; these are standalone and
 * build against the headers of the openssl-port ref under test.
 */
#ifndef KKTLS_CVE_COMMON_H
#define KKTLS_CVE_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

/* Returns 1 for the benign "control" run, 0 for the "attack" run (default). */
static int cve_is_control(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "control") == 0)
        return 1;
    if (argc > 1 && strcmp(argv[1], "attack") == 0)
        return 0;
    /* default: attack */
    return 0;
}

/* Marker: about to enter the call under test. */
static void cve_call(const char *fn)
{
    printf("KKTLS_CVE_CALL=%s\n", fn);
    fflush(stdout);
}

/* Marker: the call under test returned. */
static void cve_reached(const char *fn)
{
    printf("KKTLS_CVE_REACHED=%s\n", fn);
    fflush(stdout);
}

/* Verdict of the call under test, printed after cve_reached(): one word
 * (accepted|rejected for hang, correct|wrong for kat; anything else is an
 * ERROR in the harness) and one detail token without spaces (e.g. len=1234,
 * the error reason). Only the last KKTLS_CVE_RESULT line counts. */
static void cve_result(const char *verdict, const char *detail)
{
    printf("KKTLS_CVE_RESULT=%s %s\n", verdict, detail && *detail ? detail : "-");
    fflush(stdout);
}

/* Print peak resident set size in KiB for the mem class. getrusage(2) is used
 * instead of /usr/bin/time because the Ubuntu 14.04 build container has no
 * time(1); ru_maxrss is in KiB on Linux (and under qemu-user). */
static void cve_report_rss(void)
{
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) == 0)
        printf("MAXRSS_KB=%ld\n", (long)ru.ru_maxrss);
    else
        printf("MAXRSS_KB=-1\n");
    fflush(stdout);
}

#endif /* KKTLS_CVE_COMMON_H */
