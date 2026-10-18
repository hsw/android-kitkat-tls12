/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host test of kktls_compat.c (run-host-tests.sh builds it twice):
 *   -DKK_FAKE  getauxval on fake 32-bit auxv files (the device layout: uint32 type/value pairs), a FIFO that hands
 *              the vector over in 5-byte pieces, missing/empty/unterminated files (0, errno kept, one warning);
 *              the fortify functions: correct results within bounds, abort() with bionic's FATAL "libc" line beyond
 *   (none)     getauxval on the host's own /proc/self/auxv (native word) against the C library's getauxval
 * The exports are renamed (kk_*) so they do not collide with the host C library's functions of the same name; a
 * stub __android_log_print writes "LOG <prio> <tag> <message>" to stderr, which the abort cases capture.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define KK_SYM(name) kk_##name
#define KKTLS_COMPAT_GETAUXVAL 1
#define KKTLS_COMPAT_FORTIFY 1
#ifdef KK_FAKE
static const char *kk_test_auxv = "/nonexistent";
#define KKTLS_AUXV_PATH kk_test_auxv
#define KKTLS_AUXV_WORD uint32_t
#endif

static int log_count;
int __android_log_print(int prio, const char *tag, const char *fmt, ...) {
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    log_count++;
    fprintf(stderr, "LOG %d %s %s", prio, tag, msg);
    fflush(stderr);
    return 1;
}

#include "../kktls_compat.c"

static int failures, cases;

static void check(int good, const char *what) {
    cases++;
    if (!good) {
        failures++;
    }
    printf("%s %s\n", good ? "ok  " : "FAIL", what);
}

#ifdef KK_FAKE
static char dir[256];

static const char *fake(const char *name, const uint32_t *words, size_t n) {
    static char path[512];
    FILE *f;
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    f = fopen(path, "wb");
    if (!f || fwrite(words, sizeof(uint32_t), n, f) != n || fclose(f) != 0) {
        perror(path);
        exit(2);
    }
    return path;
}

/* child: run fn, which must abort; parent: SIGABRT and the stub's log line in the child's stderr */
static void expect_abort(const char *what, void (*fn)(void), const char *want_log) {
    int p[2], status;
    char out[1024];
    ssize_t n, have = 0;
    pid_t pid;
    char label[256];
    if (pipe(p) != 0) {
        exit(2);
    }
    pid = fork();
    if (pid == 0) {
        dup2(p[1], 2);
        close(p[0]);
        fn();
        _exit(0);  /* not reached when fn aborts */
    }
    close(p[1]);
    while ((n = read(p[0], out + have, sizeof(out) - 1 - (size_t) have)) > 0) {
        have += n;
    }
    out[have] = 0;
    close(p[0]);
    waitpid(pid, &status, 0);
    snprintf(label, sizeof(label), "%s: SIGABRT and log \"LOG 7 libc %.*s\"", what, (int) strcspn(want_log, "\n"), want_log);
    {
        char want[512];
        snprintf(want, sizeof(want), "LOG 7 libc %s", want_log);
        check(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT && strcmp(out, want) == 0, label);
    }
}

static void memcpy_over(void) { char d[8], s[16] = "0123456789abcde"; kk___memcpy_chk(d, s, 9, sizeof(d)); }
static void memmove_over(void) { char d[8] = "abcdefg"; kk___memmove_chk(d, d + 1, 9, sizeof(d)); }
static void memset_over(void) { char d[8]; kk___memset_chk(d, 0, 9, sizeof(d)); }
static void strlen_over(void) { kk___strlen_chk("abcd", 4); }
static int vsn(char *d, size_t supplied, size_t dest_len, const char *fmt, ...) {
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = kk___vsnprintf_chk(d, supplied, 0, dest_len, fmt, ap);
    va_end(ap);
    return r;
}
static void vsnprintf_over(void) { char d[8]; vsn(d, 9, sizeof(d), "%d", 1); }
static char open_path[512];
static void open_creat(void) { kk___open_2(open_path, O_CREAT | O_WRONLY); }

static void fifo_writer(const char *path, const uint32_t *words, size_t n) {
    const unsigned char *b = (const unsigned char *) words;
    size_t total = n * sizeof(uint32_t), off = 0, k;
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        _exit(3);
    }
    while (off < total) {  /* 5-byte pieces: entries are split across reads */
        k = total - off < 5 ? total - off : 5;
        if (write(fd, b + off, k) != (ssize_t) k) {
            _exit(4);
        }
        off += k;
        usleep(2000);
    }
    close(fd);
    _exit(0);
}

int main(void) {
    static const uint32_t vec[] = {33, 0xffff0000u, 16, 0x002fb0d7u, 6, 4096, 17, 100, 16, 0xdeadu, 0, 0, 26, 7};
    uint32_t big[2 * 100 + 2];
    char buf[16];
    unsigned long v;
    int i, fd, before;
    const char *p;

    snprintf(dir, sizeof(dir), "%s/kktls-compat-XXXXXX", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
    if (!mkdtemp(dir)) {
        perror("mkdtemp");
        return 2;
    }
    kk_test_auxv = fake("auxv", vec, sizeof(vec) / sizeof(vec[0]));
    check(kk_getauxval(16) == 0x002fb0d7u, "AT_HWCAP: the first entry of the type (a later duplicate ignored)");
    check(kk_getauxval(6) == 4096 && kk_getauxval(17) == 100, "AT_PAGESZ, AT_CLKTCK");
    check(kk_getauxval(33) == 0xffff0000ul, "a value with the top bit set is not sign-extended");
    check(kk_getauxval(26) == 0, "AT_HWCAP2 after AT_NULL: 0 (the vector ends at AT_NULL)");
    check(kk_getauxval(25) == 0 && kk_getauxval(0) == 0, "absent type and AT_NULL itself: 0");
    check(log_count == 0, "no warning for a readable vector");

    for (i = 0; i < 100; i++) {
        big[2 * i] = 1000 + (uint32_t) i;
        big[2 * i + 1] = 5000 + (uint32_t) i;
    }
    big[2 * 99] = 16;
    big[2 * 99 + 1] = 0x1234;
    big[200] = 0;
    big[201] = 0;
    kk_test_auxv = fake("big", big, 202);
    check(kk_getauxval(16) == 0x1234 && kk_getauxval(1050) == 5050, "100 entries (several reads): the last one found");

    p = fake("fifo-unused", vec, 2);
    snprintf(open_path, sizeof(open_path), "%s/fifo", dir);
    if (mkfifo(open_path, 0600) != 0) {
        perror("mkfifo");
        return 2;
    }
    if (fork() == 0) {
        fifo_writer(open_path, vec, sizeof(vec) / sizeof(vec[0]));
    }
    kk_test_auxv = open_path;
    v = kk_getauxval(17);
    while (wait(NULL) > 0) {
    }
    check(v == 100, "FIFO in 5-byte pieces: entries split across reads are put together");
    unlink(open_path);
    (void) p;

    errno = 1234;
    before = log_count;
    kk_test_auxv = "/nonexistent/auxv";
    check(kk_getauxval(16) == 0 && errno == 1234, "missing file: 0, errno unchanged");
    check(log_count == before + 1, "missing file: one warning");
    kk_test_auxv = fake("empty", vec, 0);
    check(kk_getauxval(16) == 0 && log_count == before + 1, "empty file: 0, no second warning in the process");
    kk_auxv_warned = 0;
    kk_test_auxv = fake("unterminated", vec, 4);
    check(kk_getauxval(16) == 0x002fb0d7u && log_count == before + 1, "unterminated: a type before the end is found");
    check(kk_getauxval(6) == 0 && log_count == before + 2, "unterminated: an absent type gives 0 and a warning");

    {
        char s[16] = "0123456789abcde", d[16];
        memset(d, 'x', sizeof(d));
        check(kk___memcpy_chk(d, s, 8, 8) == d && memcmp(d, "01234567xxx", 11) == 0, "__memcpy_chk within bounds");
        check(kk___memmove_chk(s, s + 1, 5, 16) == s && memcmp(s, "123455", 6) == 0, "__memmove_chk overlapping");
        check(kk___memset_chk(d, 'z', 3, 3) == d && memcmp(d, "zzz34567", 8) == 0, "__memset_chk exact size");
        check(kk___strlen_chk("abc", 4) == 3, "__strlen_chk below the size");
        memset(buf, 'x', sizeof(buf));
        check(vsn(buf, 8, 8, "%d-%s", 12345, "ab") == 8 && strcmp(buf, "12345-a") == 0,
              "__vsnprintf_chk truncates and returns the full length");
        check(vsn(buf, 4, 16, "%s", "hello") == 5 && strcmp(buf, "hel") == 0, "__vsnprintf_chk smaller size than the buffer");
    }
    p = fake("plain", vec, 2);
    fd = kk___open_2(p, O_RDONLY);
    check(fd >= 0, "__open_2 without O_CREAT opens");
    if (fd >= 0) {
        close(fd);
    }
    snprintf(open_path, sizeof(open_path), "%s/created", dir);
    expect_abort("__memcpy_chk 9 > 8", memcpy_over, "*** memcpy buffer overflow detected ***\n");
    expect_abort("__memmove_chk 9 > 8", memmove_over, "*** memmove buffer overflow detected ***\n");
    expect_abort("__memset_chk 9 > 8", memset_over, "*** memset buffer overflow detected ***\n");
    expect_abort("__strlen_chk length 4 >= size 4", strlen_over, "*** strlen read overflow detected ***\n");
    expect_abort("__vsnprintf_chk 9 > 8", vsnprintf_over, "*** vsnprintf buffer overflow detected ***\n");
    expect_abort("__open_2 with O_CREAT", open_creat, "*** open(O_CREAT) called without specifying a mode ***\n");
    check(access(open_path, F_OK) != 0, "__open_2 with O_CREAT created nothing");
    {
        char cmd[600];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
        if (system(cmd) != 0) {
            return 2;
        }
    }
#else
int main(void) {
    /* not AT_HWCAP on x86: glibc's getauxval(AT_HWCAP) there is its own dl_hwcap, not the kernel's entry */
    static const unsigned long types[] = {
#if !defined(__x86_64__) && !defined(__i386__)
                                          AT_HWCAP,
#endif
                                          AT_HWCAP2, AT_PAGESZ, AT_CLKTCK, AT_UID, AT_EUID, AT_SECURE,
                                          AT_RANDOM, AT_PLATFORM, AT_ENTRY, 0x7fff};
    char label[128];
    size_t i;
    for (i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        snprintf(label, sizeof(label), "native /proc/self/auxv type %lu = the C library's getauxval", types[i]);
        check(kk_getauxval(types[i]) == getauxval(types[i]), label);
    }
    check(log_count == 0, "native: no warning");
#endif
    printf("%s (%d cases, %d failed)\n", failures ? "FAIL" : "PASS", cases, failures);
    return failures ? 1 : 0;
}
