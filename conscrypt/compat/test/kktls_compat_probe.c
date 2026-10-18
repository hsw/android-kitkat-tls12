/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * kktls-compat-probe: a device test of libkktls_compat.so (built in the Jelly Bean tree next to the library; a test
 * binary, never a release file).
 *
 *   kktls-compat-probe [LIBRARY]     default libkktls_compat.so (found through LD_LIBRARY_PATH or /system/lib)
 *
 * dlopen()s the library and dlsym()s every function the library may export, prints which ones it has, and for
 *   getauxval: AT_HWCAP (and its NEON bit), AT_HWCAP2, AT_PAGESZ: the values the Conscrypt library will see;
 *   each fortify function it has: one call within bounds (the result) and one beyond, in a child process, which must
 *              die in abort() (bionic's FATAL "libc" line goes to the log). The Jelly Bean abort() writes to 0xdeadbaad
 *              before it raises SIGABRT ("seg fault seems to produce better debuggerd results", libc/unistd/abort.c),
 *              so the child dies with SIGSEGV there; SIGABRT is accepted too.
 * Output lines "probe ...", last line "PROBE PASS" or "PROBE FAIL"; exit status 0 only with PASS.
 */
#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define AT_HWCAP 16
#define AT_PAGESZ 6
#define AT_HWCAP2 26
#define HWCAP_NEON (1u << 12)

static int failed;
static void *lib;

static void *sym(const char *name) {
    void *p = dlsym(lib, name);
    printf("probe export %-16s %s\n", name, p ? "yes" : "no");
    return p;
}

static void verdict(int good, const char *what) {
    printf("probe %s %s\n", good ? "ok  " : "FAIL", what);
    if (!good) {
        failed = 1;
    }
}

typedef void *(*mem_fn)(void *, const void *, size_t, size_t);
typedef void *(*set_fn)(void *, int, size_t, size_t);
typedef size_t (*strlen_fn)(const char *, size_t);
typedef int (*vsn_fn)(char *, size_t, int, size_t, const char *, va_list);
typedef int (*open_fn)(const char *, int);

static vsn_fn vsn_p;
static int vsn(char *d, size_t supplied, size_t dest_len, const char *fmt, ...) {
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = vsn_p(d, supplied, 0, dest_len, fmt, ap);
    va_end(ap);
    return r;
}

/* runs case_no in a child: 1 memcpy, 2 memmove, 3 memset, 4 strlen, 5 vsnprintf, 6 open; abort() expected */
static void child_abort(const char *what, void *fn, int case_no) {
    char d[8], s[16] = "0123456789abcde", label[128];
    int status;
    pid_t pid = fork();
    if (pid == 0) {
        switch (case_no) {
        case 1: ((mem_fn) fn)(d, s, 9, sizeof(d)); break;
        case 2: ((mem_fn) fn)(d, s, 9, sizeof(d)); break;
        case 3: ((set_fn) fn)(d, 0, 9, sizeof(d)); break;
        case 4: ((strlen_fn) fn)("abcd", 4); break;
        case 5: vsn(d, 9, sizeof(d), "%d", 1); break;
        case 6: ((open_fn) fn)("/data/local/tmp/kktls-compat-probe-must-not-exist", O_CREAT | O_WRONLY); break;
        }
        _exit(0);
    }
    waitpid(pid, &status, 0);
    snprintf(label, sizeof(label), "%s beyond bounds: abort() (status 0x%x: %s)", what, status,
             WIFSIGNALED(status) ? (WTERMSIG(status) == SIGSEGV ? "SIGSEGV, JB abort()" : WTERMSIG(status) == SIGABRT
                                    ? "SIGABRT" : "other signal") : "no signal");
    verdict(pid > 0 && WIFSIGNALED(status) && (WTERMSIG(status) == SIGABRT || WTERMSIG(status) == SIGSEGV), label);
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "libkktls_compat.so";
    unsigned long (*auxv)(unsigned long);
    void *mc, *mm, *ms, *sl, *op;
    char d[16], s[16] = "0123456789abcde";

    setvbuf(stdout, NULL, _IONBF, 0);
    lib = dlopen(path, RTLD_NOW);
    if (!lib) {
        printf("probe dlopen %s: %s\nPROBE FAIL\n", path, dlerror());
        return 1;
    }
    printf("probe dlopen %s ok\n", path);
    auxv = (unsigned long (*)(unsigned long)) sym("getauxval");
    mc = sym("__memcpy_chk");
    mm = sym("__memmove_chk");
    ms = sym("__memset_chk");
    sl = sym("__strlen_chk");
    vsn_p = (vsn_fn) sym("__vsnprintf_chk");
    op = sym("__open_2");
    if (auxv) {
        unsigned long hwcap = auxv(AT_HWCAP);
        printf("probe getauxval AT_HWCAP 0x%08lx neon %s, AT_HWCAP2 0x%08lx, AT_PAGESZ %lu\n", hwcap,
               (hwcap & HWCAP_NEON) ? "yes" : "no", auxv(AT_HWCAP2), auxv(AT_PAGESZ));
        verdict(auxv(AT_PAGESZ) == (unsigned long) sysconf(_SC_PAGESIZE), "getauxval(AT_PAGESZ) = sysconf page size");
    }
    if (mc) {
        verdict(((mem_fn) mc)(d, s, 8, sizeof(d)) == d && memcmp(d, "01234567", 8) == 0, "__memcpy_chk within bounds");
        child_abort("__memcpy_chk", mc, 1);
    }
    if (mm) {
        verdict(((mem_fn) mm)(s, s + 1, 5, sizeof(s)) == s && memcmp(s, "123455", 6) == 0, "__memmove_chk within bounds");
        child_abort("__memmove_chk", mm, 2);
    }
    if (ms) {
        verdict(((set_fn) ms)(d, 'z', 3, 3) == d && memcmp(d, "zzz3", 4) == 0, "__memset_chk within bounds");
        child_abort("__memset_chk", ms, 3);
    }
    if (sl) {
        verdict(((strlen_fn) sl)("abc", 4) == 3, "__strlen_chk within bounds");
        child_abort("__strlen_chk", sl, 4);
    }
    if (vsn_p) {
        verdict(vsn(d, 8, 8, "%d-%s", 12345, "ab") == 8 && strcmp(d, "12345-a") == 0, "__vsnprintf_chk within bounds");
        child_abort("__vsnprintf_chk", (void *) vsn_p, 5);
    }
    if (op) {
        int fd = ((open_fn) op)("/proc/self/auxv", O_RDONLY);
        verdict(fd >= 0, "__open_2 O_RDONLY opens");
        if (fd >= 0) {
            close(fd);
        }
        child_abort("__open_2 O_CREAT", op, 6);
        verdict(access("/data/local/tmp/kktls-compat-probe-must-not-exist", F_OK) != 0, "__open_2 O_CREAT created nothing");
    }
    printf("PROBE %s\n", failed ? "FAIL" : "PASS");
    return failed;
}
