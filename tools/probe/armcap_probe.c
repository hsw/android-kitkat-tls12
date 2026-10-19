/* SPDX-License-Identifier: Apache-2.0 */
/*
 * armcap_probe: print the OPENSSL_armcap_P word of the device's libcrypto.so (the ARM capability bits of 1.0.1u
 * arm_arch.h: 1 = ARMV7_NEON, 2 = ARMV7_TICK). The kktls 4.4 ARM libcrypto sets ARMV7_NEON from AT_HWCAP when it is
 * loaded (armcap.c, a constructor); OPENSSL_armcap=<n> in the environment overrides it (masked to ARMV7_NEON), so
 * `OPENSSL_armcap=0 armcap_probe` must print 0. A library whose OPENSSL_cpuid_setup is a stub prints 0 either way.
 *
 *   armcap_probe [LIB]     LIB default libcrypto.so (the linker's search path: /system/lib)
 *   prints "OPENSSL_armcap_P=<n>"; exit 0, 1 when LIB does not load or has no OPENSSL_armcap_P (reason on stderr)
 *
 * Build (NDK r25 or older: API 19 is the minimum it targets; r26 starts at 21), then push to /data/local/tmp:
 *   $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi19-clang -O2 -Wall -Wextra \
 *     -o armcap_probe tools/probe/armcap_probe.c -ldl
 */
#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char **argv) {
    const char *lib = argc > 1 ? argv[1] : "libcrypto.so";
    void *h = dlopen(lib, RTLD_NOW);
    if (h == NULL) {
        fprintf(stderr, "armcap_probe: dlopen %s: %s\n", lib, dlerror());
        return 1;
    }
    const unsigned int *cap = dlsym(h, "OPENSSL_armcap_P");
    if (cap == NULL) {
        fprintf(stderr, "armcap_probe: dlsym OPENSSL_armcap_P in %s: %s\n", lib, dlerror());
        return 1;
    }
    printf("OPENSSL_armcap_P=%u\n", *cap);
    return 0;
}
