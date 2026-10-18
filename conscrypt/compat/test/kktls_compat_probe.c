/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * kktls-compat-probe: a device test of libkktls_compat.so (built in the Jelly Bean tree next to the library; a test
 * binary, never a release file).
 *
 *   kktls-compat-probe [--uid UID] [LIBRARY]   default libkktls_compat.so (found through LD_LIBRARY_PATH or /system/lib)
 *   kktls-compat-probe --uid UID --exec PROGRAM [ARG...]
 *
 * First the probe reads its own AT_HWCAP/AT_HWCAP2 from /proc/self/auxv (the reference). With --uid (run as root) it
 * then drops to UID in the zygote's order for an app without DEBUG_ENABLE_DEBUGGER (4.1/4.2 dalvik_system_Zygote.cpp:
 * setgroups, setgid, setuid, no PR_SET_DUMPABLE): supplementary group inet (3003), gid and uid UID. setuid() from root
 * leaves the process not dumpable (fs.suid_dumpable 0), so /proc/self/auxv belongs to root and open() fails with
 * EACCES, as in every app of a user build and in system_server. The probe prints the dumpable flag and the errno.
 * With --exec it then runs PROGRAM in that condition. exec() makes a process dumpable again, except when the program
 * file is not readable for the caller (the kernel's would_dump(): fs.suid_dumpable applies), so PROGRAM must be an
 * execute-only copy (mode 0711, owner root), e.g. of app_process with a TLS probe; unlike a set-id exec this leaves
 * AT_SECURE clear, so the environment (LD_LIBRARY_PATH, which 4.2's System needs) is kept. Test only.
 *
 * Without --exec it dlopen()s the library and dlsym()s every function the library may export, prints which ones it has,
 * and for
 *   getauxval: AT_HWCAP (and its NEON bit), AT_HWCAP2, AT_PAGESZ: the values the Conscrypt library will see. AT_HWCAP
 *              and AT_HWCAP2 must equal the reference (with --uid: derived from /proc/cpuinfo, which on a kernel that
 *              names every bit it sets is the same value); AT_PAGESZ must be the page size, with --uid 0 (unreadable);
 * Output lines "probe ...", last line "PROBE PASS" or "PROBE FAIL"; exit status 0 only with PASS.
 */
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define AT_HWCAP 16
#define AT_PAGESZ 6
#define AT_HWCAP2 26
#define HWCAP_NEON (1u << 12)
#define AID_INET 3003

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

/* the value of a type in this process's own /proc/self/auxv (32-bit pairs): 0 absent, -1 unreadable */
static long long own_auxv(unsigned long type) {
    unsigned int v[256];
    ssize_t n;
    int fd = open("/proc/self/auxv", O_RDONLY), i;
    if (fd < 0) {
        return -1;
    }
    n = read(fd, v, sizeof(v));
    close(fd);
    for (i = 0; n > 0 && i + 1 < n / 4 && v[i] != 0; i += 2) {
        if (v[i] == type) {
            return v[i + 1];
        }
    }
    return n > 0 ? 0 : -1;
}

static void read_line(const char *path, char *out, size_t size) {
    int fd = open(path, O_RDONLY);
    ssize_t n = fd < 0 ? -1 : read(fd, out, size - 1);
    if (fd >= 0) {
        close(fd);
    }
    out[n > 0 ? n : 0] = '\0';
    if (n > 0 && out[n - 1] == '\n') {
        out[n - 1] = '\0';
    }
}

/* the zygote's order for an app without DEBUG_ENABLE_DEBUGGER */
static int drop(unsigned uid) {
    gid_t groups[1] = {AID_INET};
    char sd[16];
    int fd, err;
    if (setgroups(1, groups) != 0 || setgid(uid) != 0 || setuid(uid) != 0) {
        printf("probe drop to uid %u: %s (run as root)\n", uid, strerror(errno));
        return -1;
    }
    read_line("/proc/sys/fs/suid_dumpable", sd, sizeof(sd));
    fd = open("/proc/self/auxv", O_RDONLY);
    err = errno;
    printf("probe as uid %u gid %u egid %u: dumpable %d (fs.suid_dumpable %s), /proc/self/auxv: %s\n", (unsigned) getuid(),
           (unsigned) getgid(), (unsigned) getegid(), prctl(PR_GET_DUMPABLE, 0, 0, 0, 0), sd,
           fd >= 0 ? "opened" : strerror(err));
    if (fd >= 0) {
        close(fd);
    }
    verdict(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0 && fd < 0 && err == EACCES,
            "not dumpable and /proc/self/auxv EACCES (the condition of a non-debuggable app)");
    return 0;
}

int main(int argc, char **argv) {
    const char *path = "libkktls_compat.so";
    long long ref_hwcap = own_auxv(AT_HWCAP), ref_hwcap2 = own_auxv(AT_HWCAP2);
    int uid = -1, a = 1;
    unsigned long (*auxv)(unsigned long);
    void *mc, *mm, *ms, *sl, *op;
    char d[16], s[16] = "0123456789abcde";

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("probe reference /proc/self/auxv AT_HWCAP 0x%08llx, AT_HWCAP2 0x%08llx (-1 unreadable)\n", ref_hwcap,
           ref_hwcap2);
    if (a + 1 < argc && strcmp(argv[a], "--uid") == 0) {
        uid = atoi(argv[a + 1]);
        a += 2;
    }
    if (a + 1 < argc && strcmp(argv[a], "--exec") == 0) {
        if (uid <= 0 || drop((unsigned) uid) != 0 || failed) {
            printf("PROBE FAIL\n");
            return 1;
        }
        printf("probe exec %s\n", argv[a + 1]);
        execv(argv[a + 1], argv + a + 1);
        printf("probe exec %s: %s\nPROBE FAIL\n", argv[a + 1], strerror(errno));
        return 1;
    }
    if (a < argc) {
        path = argv[a];
    }
    if (uid >= 0 && drop((unsigned) uid) != 0) {
        printf("PROBE FAIL\n");
        return 1;
    }
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
        unsigned long hwcap = auxv(AT_HWCAP), hwcap2 = auxv(AT_HWCAP2), pagesz = auxv(AT_PAGESZ);
        printf("probe getauxval AT_HWCAP 0x%08lx neon %s, AT_HWCAP2 0x%08lx, AT_PAGESZ %lu\n", hwcap,
               (hwcap & HWCAP_NEON) ? "yes" : "no", hwcap2, pagesz);
        verdict(ref_hwcap >= 0 && hwcap == (unsigned long) ref_hwcap && hwcap2 == (unsigned long) ref_hwcap2,
                uid >= 0 ? "getauxval(AT_HWCAP/AT_HWCAP2) from /proc/cpuinfo = the reference from /proc/self/auxv"
                         : "getauxval(AT_HWCAP/AT_HWCAP2) = the reference from /proc/self/auxv");
        verdict(uid >= 0 ? pagesz == 0 : pagesz == (unsigned long) sysconf(_SC_PAGESIZE),
                uid >= 0 ? "getauxval(AT_PAGESZ) = 0 (vector unreadable; only the HWCAPs come from /proc/cpuinfo)"
                         : "getauxval(AT_PAGESZ) = sysconf page size");
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
        int fd = ((open_fn) op)("/proc/cpuinfo", O_RDONLY);  /* world-readable: also with --uid */
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
