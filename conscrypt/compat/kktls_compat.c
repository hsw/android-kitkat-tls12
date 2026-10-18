/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * libkktls_compat.so: the bionic functions that the Conscrypt 2.6-alpha2 JNI library (libkktls_conscrypt_jni.so)
 * imports and that the Android 4.1/4.2 libc does not have. jb_needed.py adds this library to the JNI library's
 * DT_NEEDED list (last); the Jelly Bean linkers resolve an import in libc/libm/libdl/liblog first, so this library
 * only fills the gaps, and each base and ABI gets exactly its gaps (Android.mk; check_prebuilt.py JB_MISSING):
 *
 *   4.2 ARM  getauxval                                   (KKTLS_COMPAT_GETAUXVAL)
 *   4.1 ARM  getauxval + the six fortify functions below  (KKTLS_COMPAT_GETAUXVAL, KKTLS_COMPAT_FORTIFY)
 *   4.1 x86  the six fortify functions                    (KKTLS_COMPAT_FORTIFY)
 *
 * getauxval: bionic 4.3 returns the value of the first auxiliary vector entry of that type, 0 when there is none
 * (errno untouched). BoringSSL (crypto/cpu_arm_linux.cc) asks for AT_HWCAP (NEON) and, with NEON, AT_HWCAP2
 * (AES/PMULL/SHA; it reads /proc/cpuinfo itself when that is 0). bionic reads the vector the kernel put on the
 * initial stack (__libc_auxv, private to libc); a separate library reads the same vector from /proc/self/auxv.
 * When that file cannot be read the result is 0 as for an absent type (BoringSSL then runs its non-NEON code, which
 * is correct, only slower) and one warning per process goes to the log, so a 0 never passes silently.
 *
 * Fortify functions: the checks, messages and abort() of bionic android-4.2.2_r1 (libc/string/__memcpy_chk.c,
 * __memmove_chk.c, __memset_chk.c, __strlen_chk.c, libc/stdio/__vsnprintf_chk.c, libc/unistd/open.c __open_2): on a
 * violation, a FATAL "libc" log line with bionic's text, then abort(); otherwise the plain function. bionic also
 * writes an event-log entry (BIONIC_EVENT_*_BUFFER_OVERFLOW) through a libc-private function that 4.1 does not
 * export; that entry is left out. __open_2 calls open(), which on 4.1 adds O_LARGEFILE as 4.2's __open_2 does.
 *
 * Build: -fvisibility=hidden (only the functions below are exported), -U_FORTIFY_SOURCE (a fortified memcpy inside
 * __memcpy_chk would call itself), NEEDED libc and liblog only. The host test (test/) compiles this file with
 * KK_SYM renaming the exports and KKTLS_AUXV_PATH / KKTLS_AUXV_WORD pointing at fake 32-bit auxv files.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef KK_SYM
#define KK_SYM(name) name
#endif
#define KK_EXPORT __attribute__((visibility("default")))

#define KK_LOG_WARN 5   /* ANDROID_LOG_WARN */
#define KK_LOG_FATAL 7  /* ANDROID_LOG_FATAL */
int __android_log_print(int prio, const char *tag, const char *fmt, ...);  /* liblog */

#if defined(KKTLS_COMPAT_GETAUXVAL)
#ifndef KKTLS_AUXV_PATH
#define KKTLS_AUXV_PATH "/proc/self/auxv"
#endif
#ifndef KKTLS_AUXV_WORD
#define KKTLS_AUXV_WORD unsigned long  /* the native word: 32 bits on every Android ABI this is built for */
#endif
#define KK_AT_NULL 0

static volatile int kk_auxv_warned;

static void kk_auxv_warn(const char *what, int err, unsigned long type) {
    if (kk_auxv_warned) {
        return;
    }
    kk_auxv_warned = 1;
    __android_log_print(KK_LOG_WARN, "kktls_compat", "%s %s (%s): getauxval(%lu) returns 0 (warned once per process)",
                        KKTLS_AUXV_PATH, what, err ? strerror(err) : "no AT_NULL", type);
}

KK_EXPORT unsigned long KK_SYM(getauxval)(unsigned long type) {
    KKTLS_AUXV_WORD buf[64];  /* 32 entries per read; a partial entry carries over to the next read */
    unsigned char *bytes = (unsigned char *) buf;
    const size_t entry = 2 * sizeof(KKTLS_AUXV_WORD);
    size_t have = 0, i, used;
    unsigned long value = 0;
    int saved = errno, fd, end = 0;
    ssize_t n;

    do {
        fd = open(KKTLS_AUXV_PATH, O_RDONLY);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        kk_auxv_warn("cannot be opened", errno, type);
        errno = saved;
        return 0;
    }
    while (!end) {
        n = read(fd, bytes + have, sizeof(buf) - have);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            kk_auxv_warn(n < 0 ? "cannot be read" : "ends early", n < 0 ? errno : 0, type);
            break;
        }
        have += (size_t) n;
        for (used = 0; used + entry <= have; used += entry) {
            const KKTLS_AUXV_WORD *e = (const KKTLS_AUXV_WORD *) (bytes + used);
            if (e[0] == KK_AT_NULL) {
                end = 1;
                break;
            }
            if (e[0] == type) {
                value = (unsigned long) e[1];
                end = 1;
                break;
            }
        }
        for (i = 0; used + i < have; i++) {  /* keep a partial entry (fewer than 8 bytes) at the front */
            bytes[i] = bytes[used + i];
        }
        have -= used;
    }
    close(fd);
    errno = saved;
    return value;
}
#endif

#if defined(KKTLS_COMPAT_FORTIFY)
static void kk_fortify_fail(const char *msg) __attribute__((noreturn));
static void kk_fortify_fail(const char *msg) {
    __android_log_print(KK_LOG_FATAL, "libc", "%s", msg);
    abort();
}

KK_EXPORT void *KK_SYM(__memcpy_chk)(void *dest, const void *src, size_t copy_amount, size_t dest_len) {
    if (__builtin_expect(copy_amount > dest_len, 0)) {
        kk_fortify_fail("*** memcpy buffer overflow detected ***\n");
    }
    return memcpy(dest, src, copy_amount);
}

KK_EXPORT void *KK_SYM(__memmove_chk)(void *dest, const void *src, size_t len, size_t dest_len) {
    if (len > dest_len) {
        kk_fortify_fail("*** memmove buffer overflow detected ***\n");
    }
    return memmove(dest, src, len);
}

KK_EXPORT void *KK_SYM(__memset_chk)(void *dest, int c, size_t n, size_t dest_len) {
    if (n > dest_len) {
        kk_fortify_fail("*** memset buffer overflow detected ***\n");
    }
    return memset(dest, c, n);
}

KK_EXPORT size_t KK_SYM(__strlen_chk)(const char *s, size_t s_len) {
    size_t ret = strlen(s);
    if (__builtin_expect(ret >= s_len, 0)) {
        kk_fortify_fail("*** strlen read overflow detected ***\n");
    }
    return ret;
}

KK_EXPORT int KK_SYM(__vsnprintf_chk)(char *dest, size_t supplied_size, int flags, size_t dest_len_from_compiler,
                                      const char *format, va_list va) {
    (void) flags;
    if (supplied_size > dest_len_from_compiler) {
        kk_fortify_fail("*** vsnprintf buffer overflow detected ***\n");
    }
    return vsnprintf(dest, supplied_size, format, va);
}

KK_EXPORT int KK_SYM(__open_2)(const char *pathname, int flags) {
    if (flags & O_CREAT) {
        kk_fortify_fail("*** open(O_CREAT) called without specifying a mode ***\n");
    }
    return open(pathname, flags);
}
#endif
