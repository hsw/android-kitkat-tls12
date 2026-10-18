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
 * That file is mode 0400 and belongs to root while the process is not dumpable: every app the zygote forks without
 * DEBUG_ENABLE_DEBUGGER (all apps of a user build, ro.debuggable=0) and system_server, so open() fails with EACCES
 * there. When the vector cannot be read, AT_HWCAP and AT_HWCAP2 come from the first "Features" line of /proc/cpuinfo
 * (world-readable; the kernel prints one word per set bit, kk_hwcap_words below), any other type is 0, and one
 * warning per process goes to the log with the cause and the value, so neither a fallback nor a 0 passes silently.
 * Without the fallback BoringSSL would run its non-NEON code in those processes (correct, only slower). No cache:
 * BoringSSL asks twice per process (CRYPTO_once), and nothing is shared between calls except the warning flag.
 *
 * Fortify functions: the checks, messages and abort() of bionic android-4.2.2_r1 (libc/string/__memcpy_chk.c,
 * __memmove_chk.c, __memset_chk.c, __strlen_chk.c, libc/stdio/__vsnprintf_chk.c, libc/unistd/open.c __open_2): on a
 * violation, a FATAL "libc" log line with bionic's text, then abort(); otherwise the plain function. bionic also
 * writes an event-log entry (BIONIC_EVENT_*_BUFFER_OVERFLOW) through a libc-private function that 4.1 does not
 * export; that entry is left out. __open_2 calls open(), which on 4.1 adds O_LARGEFILE as 4.2's __open_2 does.
 *
 * Build: -fvisibility=hidden (only the functions below are exported), -U_FORTIFY_SOURCE (a fortified memcpy inside
 * __memcpy_chk would call itself), NEEDED libc and liblog only. The host test (test/) compiles this file with
 * KK_SYM renaming the exports, KKTLS_AUXV_PATH / KKTLS_AUXV_WORD pointing at fake 32-bit auxv files and
 * KKTLS_CPUINFO_PATH at fake cpuinfo files.
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
#ifndef KKTLS_CPUINFO_PATH
#define KKTLS_CPUINFO_PATH "/proc/cpuinfo"
#endif
#ifndef KKTLS_AUXV_WORD
#define KKTLS_AUXV_WORD unsigned long  /* the native word: 32 bits on every Android ABI this is built for */
#endif
#define KK_AT_NULL 0
#define KK_AT_HWCAP 16
#define KK_AT_HWCAP2 26

/*
 * The words of the kernel's "Features" line, index = bit: hwcap_str[] and hwcap2_str[] of arch/arm/kernel/setup.c
 * (= the HWCAP_* and HWCAP2_* bits of arch/arm/include/uapi/asm/hwcap.h); the arm64 kernel prints the same words for a
 * 32-bit process (compat_hwcap_str[], compat_hwcap2_str[]). A bit never moved: kernel 3.0 prints the first 19 words,
 * newer kernels append. BoringSSL reads "neon" (HWCAP) and "aes", "pmull", "sha1", "sha2" (HWCAP2).
 */
static const char *const kk_hwcap_words[] = {
    "swp", "half", "thumb", "26bit", "fastmult", "fpa", "vfp", "edsp", "java", "iwmmxt", "crunch", "thumbee", "neon",
    "vfpv3", "vfpv3d16", "tls", "vfpv4", "idiva", "idivt", "vfpd32", "lpae", "evtstrm", "fphp", "asimdhp", "asimddp",
    "asimdfhm", "asimdbf16", "i8mm",
};
static const char *const kk_hwcap2_words[] = {"aes", "pmull", "sha1", "sha2", "crc32", "sb", "ssbs"};

static int kk_auxv_warned;

static int kk_is_blank(char c) {
    return c == ' ' || c == '\t' || c == '\r';
}

/* the bit of one word of a Features line in a table, or 0 for a word the table does not have */
static unsigned long kk_word_bit(const char *const *words, size_t count, const char *w, size_t len) {
    size_t i;
    for (i = 0; i < count; i++) {
        if (strlen(words[i]) == len && memcmp(words[i], w, len) == 0) {
            return 1ul << i;
        }
    }
    return 0;
}

/* one line of cpuinfo: 1 and the bits of its words if the key before the first ':' is "Features", else 0 */
static int kk_features_line(const char *line, size_t len, unsigned long *hwcap, unsigned long *hwcap2) {
    const char *colon = memchr(line, ':', len);
    size_t k, i, w;
    if (!colon) {
        return 0;
    }
    for (k = 0; k < (size_t) (colon - line) && kk_is_blank(line[k]); k++) {
    }
    for (i = (size_t) (colon - line); i > k && kk_is_blank(line[i - 1]); i--) {
    }
    if (i - k != 8 || memcmp(line + k, "Features", 8) != 0) {
        return 0;
    }
    *hwcap = 0;
    *hwcap2 = 0;
    for (i = (size_t) (colon - line) + 1; i < len; i = w) {
        for (; i < len && kk_is_blank(line[i]); i++) {
        }
        for (w = i; w < len && !kk_is_blank(line[w]); w++) {
        }
        if (w > i) {
            *hwcap |= kk_word_bit(kk_hwcap_words, sizeof(kk_hwcap_words) / sizeof(kk_hwcap_words[0]), line + i, w - i);
            *hwcap2 |= kk_word_bit(kk_hwcap2_words, sizeof(kk_hwcap2_words) / sizeof(kk_hwcap2_words[0]), line + i,
                                   w - i);
        }
    }
    return 1;
}

/*
 * AT_HWCAP and AT_HWCAP2 from the first Features line of cpuinfo: 1 when the file was read (both 0 without a Features
 * line), 0 when it cannot be opened or read. A line longer than the buffer is skipped (a Features line is < 300 bytes).
 */
static int kk_cpuinfo_hwcaps(unsigned long *hwcap, unsigned long *hwcap2) {
    char line[1024], buf[512];
    size_t len = 0;
    int fd, skip = 0, found = 0;
    ssize_t n, i;

    *hwcap = 0;
    *hwcap2 = 0;
    do {
        fd = open(KKTLS_CPUINFO_PATH, O_RDONLY);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        return 0;
    }
    while (!found) {
        n = read(fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0) {
            close(fd);
            return 0;
        }
        if (n == 0) {
            if (len > 0 && !skip) {
                kk_features_line(line, len, hwcap, hwcap2);
            }
            break;
        }
        for (i = 0; i < n && !found; i++) {
            if (buf[i] == '\n') {
                found = !skip && kk_features_line(line, len, hwcap, hwcap2);
                len = 0;
                skip = 0;
            } else if (len < sizeof(line)) {
                line[len++] = buf[i];
            } else {
                skip = 1;
            }
        }
    }
    close(fd);
    return 1;
}

/*
 * The vector cannot be read (what, err: why). AT_HWCAP and AT_HWCAP2 come from cpuinfo, any other type is 0. The
 * first time in the process (any thread) one warning names the cause and the value.
 */
static unsigned long kk_auxv_fallback(const char *what, int err, unsigned long type) {
    unsigned long hwcap, hwcap2, value = 0;
    int have = 0;
    if (type == KK_AT_HWCAP || type == KK_AT_HWCAP2) {
        have = kk_cpuinfo_hwcaps(&hwcap, &hwcap2);
        if (have) {
            value = type == KK_AT_HWCAP ? hwcap : hwcap2;
        }
    }
    if (__sync_bool_compare_and_swap(&kk_auxv_warned, 0, 1)) {
        if (have) {
            __android_log_print(KK_LOG_WARN, "kktls_compat",
                                "%s %s (%s): getauxval(%lu) = 0x%08lx from the Features line of %s (warned once per "
                                "process)", KKTLS_AUXV_PATH, what, err ? strerror(err) : "no AT_NULL", type, value,
                                KKTLS_CPUINFO_PATH);
        } else {
            __android_log_print(KK_LOG_WARN, "kktls_compat", "%s %s (%s): getauxval(%lu) returns 0%s%s (warned once "
                                "per process)", KKTLS_AUXV_PATH, what, err ? strerror(err) : "no AT_NULL", type,
                                type == KK_AT_HWCAP || type == KK_AT_HWCAP2 ? ", cannot read " : "",
                                type == KK_AT_HWCAP || type == KK_AT_HWCAP2 ? KKTLS_CPUINFO_PATH : "");
        }
    }
    return value;
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
        value = kk_auxv_fallback("cannot be opened", errno, type);
        errno = saved;
        return value;
    }
    while (!end) {
        n = read(fd, bytes + have, sizeof(buf) - have);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            int err = n < 0 ? errno : 0;
            close(fd);
            value = kk_auxv_fallback(n < 0 ? "cannot be read" : "ends early", err, type);
            errno = saved;
            return value;
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
