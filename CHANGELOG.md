# Changelog

## v5 (unreleased)

Android 4.3, 4.2 and 4.1.2 (Jelly Bean): TLS 1.3 (layer D), ARM and x86. On every Android version the layer D default
factory now checks for NEON before it loads the ARM Conscrypt library.

### New

- `kktls-conscrypt-4.3-<abi>-<rel>.zip`, `kktls-conscrypt-4.2-<abi>-<rel>.zip`, `kktls-conscrypt-4.1-<abi>-<rel>.zip`
  (`armeabi-v7a`, `x86`): layer D on Jelly Bean, the same Conscrypt 2.6-alpha2 as on 4.4. Each installs on the releases
  of its java zip (4.3.x, 4.2.x, 4.1.2) after the java zip of the same release; the restore zip removes it. The default
  factory comes with the java zip (libcore patch 0033 of each Jelly Bean series, the source of 4.4's 0025). On Jelly
  Bean it uses Conscrypt's inner `org.conscrypt.OpenSSLSocketFactoryImpl`, because the adapter that Conscrypt returns
  below API 22 makes sockets of a 4.4-only class; without the layer D files, or when they fail to load, it falls back to
  the platform factory `org.apache.harmony.xnet.provider.jsse.OpenSSLSocketFactoryImpl` (layer A, as in v4). The kill
  switch `persist.kktls.conscrypt=0` works as on 4.4.
- The Jelly Bean `kktls-conscrypt.jar`: `conscrypt/jb_charsets.py` replaces `java.nio.charset.StandardCharsets` (API 19,
  read on the ALPN, keying-material, PSK and scrypt paths) with an own class, then `d8 --min-api 16`
  (`conscrypt/mkstage.py --jb`). One pinned dex jar for all three versions.
- `libkktls_compat.so` (`conscrypt/compat/`), a fourth layer D file in the 4.2 ARM, 4.1 ARM and 4.1 x86 zips: the bionic
  functions that the Conscrypt library imports and these versions lack (`getauxval`; on 4.1 also `__memcpy_chk`,
  `__memmove_chk`, `__memset_chk`, `__open_2`, `__strlen_chk`, `__vsnprintf_chk`), built in the AOSP tree of each
  version. `getauxval` reads `/proc/self/auxv`, and in a process that cannot open it (not dumpable: every app of a user
  build) takes `AT_HWCAP`/`AT_HWCAP2` from the `Features` line of `/proc/cpuinfo`. `conscrypt/jb_needed.py` turns the
  library's `DT_SONAME` entry into `DT_NEEDED libkktls_compat.so` (pinned output); 4.3 and 4.2 x86 use the aar library
  unchanged.
- Checks: `conscrypt/check_prebuilt.py --jb --base <ver> [--compat FILE]` against the bionic exports of our own 4.1.2,
  4.2.2 and 4.3 builds (`conscrypt/bionic4[123]-exports{,-x86}.txt`); `conscrypt/apicheck.py --api 16|17|18`
  (`apicheck-allow-jb.txt`); host tests of the compat library (`conscrypt/compat/test/`) and of the Jelly Bean cases of
  the default factory; `tools/check_44_payload.py`, run in CI, compares the `/system` files of the 4.4 zips with v4.
- `tools/kktls-jb-openssl-build.sh`: `conscrypt` and `compat` lines in `patches/jb/targets.txt` and a `stage` step;
  `tools/mkzips.sh --jb` packs the Jelly Bean conscrypt zips.

### Changed

- The 4.4 java zips: `core.jar` and `core-libart.jar` carry the new default factory (libcore 0025). For an ARM library
  it checks for NEON (`AT_HWCAP` from `/proc/self/auxv`, else the `Features` line of `/proc/cpuinfo`) before loading
  Conscrypt; without NEON it uses the platform factory and logs once. It checks the ELF headers of
  `libkktls_compat.so` too when that file exists. A failure to make the Conscrypt factory after the provider loaded is
  now kept for the process like a load failure: no new TLS context and no new log line on later constructions. Every
  other file of the 4.4 zips installs the same bytes as v4.
- The Jelly Bean java zips: `core.jar` carries the default factory (0033). Without the layer D files it is the platform
  factory, as in v4.
- `installer/checks.sh`: `KK_D_FILES` lists `system/lib/libkktls_compat.so`, so the restore removes it with the other
  layer D files, also when the conscrypt zip's own backup is gone. Every zip carries this file; on 4.4 the extra path
  finds nothing.

### Fixed

- SIGILL on ARMv7 CPUs without NEON with layer D installed (4.4, since v1): the aar's ARM Conscrypt library is built
  with NEON as its baseline and killed every process that used the default `SSLSocketFactory`, inside the linker,
  before the Java fallback could run. Such a CPU now stays on layer A. Checked on Jelly Bean ARM emulator kernels
  without NEON (the same source as 4.4) and in host tests.

## v4

Android 4.3, 4.2 and 4.1.2: the x86 builds of the Java TLS layer (layer A) join the release. TLS 1.3 stays 4.4
only.

### New

- `kktls-java-4.3-x86-<rel>.zip`, `kktls-java-4.2-x86-<rel>.zip`, `kktls-java-4.1-x86-<rel>.zip`: the x86 builds of the
  Jelly Bean java zips join the release set. Each was installed, booted and restored on an AOSP `full_x86-eng` build of
  its version (no dexpreopt, KVM) with the same results as the ARM zip.

### Changed

- `tools/mkzips.sh` packs the Jelly Bean java zips for both ABIs into `--out`; the `--out-unreleased` option is gone,
  and CI no longer uploads the `zips-unreleased` artifact.

## v3

Android 4.3, 4.2 and 4.1.2 (Jelly Bean, API 16-18): the Java TLS layer (layer A), ARM only. TLS 1.3 stays 4.4 only.

### New

- `kktls-java-4.3-armeabi-v7a-<rel>.zip`: `core.jar` and `libjavacore.so` built from `android-4.3_r3` with the libcore
  series of 4.4 in the Jelly Bean layout (`patches/jb/4.3/libcore/`): TLS 1.1 and 1.2 on by default, the 13 default
  suites, SNI on every client path, stricter wildcard matching, the intermediate CA fixes. `HttpsURLConnection`
  (`libcore.net.http` on 4.3, no okhttp) retries a failed handshake over TLSv1 with `TLS_FALLBACK_SCSV` instead of
  SSLv3. Installs on 4.3.x (AOSP: 4.3, 4.3.1) after the 4.3 openssl zip; the restore zip undoes it.
- `kktls-java-4.2-armeabi-v7a-<rel>.zip`: the same for `android-4.2.2_r1` (`patches/jb/4.2/libcore/`, the 4.3 series
  ported to 4.2: `int` handles in `NativeCrypto`, `SSL_MODE_HANDSHAKE_CUTTHROUGH` moved from the stock `0x40` to the
  1.0.1u value `0x200`, and the session reuse of 4.3's `OpenSSLSocketImpl`, which 4.2 lacks and OpenSSL 1.0.1u session
  tickets need). Installs on 4.2.x (AOSP: 4.2, 4.2.1, 4.2.2) after the 4.2 openssl zip.
- `kktls-java-4.1-armeabi-v7a-<rel>.zip`: the same for `android-4.1.2_r2` (`patches/jb/4.1/libcore/`, the 4.2 series
  ported to 4.1: the older `TrustManagerImpl` chain loop and `ScopedLocalRef`). Installs on 4.1.2 only (AOSP:
  4.1.2; 4.1.1 has another libcore JNI) after the 4.1 openssl zip.
- The x86 builds of these zips are packed only with `tools/mkzips.sh --out-unreleased DIR` (CI: artifact
  `zips-unreleased`), not released until they have booted on an x86 system of their version.
- `tools/kktls-jb-openssl-build.sh` builds `core` and `libjavacore` for a base with `java` lines in
  `patches/jb/targets.txt` and checks them (`classes.dex` present, `libjavacore.so` exports and `NEEDED` against stock);
  `tools/kktls-jb-remap.py` maps the 4.4 libcore series to the Jelly Bean paths; `tools/check_jni_signatures.py`
  compares the Java `native` declarations with the JNI registration table; `tools/check_tls_lists.py --base <ver>`
  reads the Jelly Bean sources, including the `libcore.net.http` fallback.

### Unchanged

- The 4.4 zips, the CA store and the restore zip: same payload and installer. Packed with the v2 name, the CA store
  and restore zips of this tree equal the v2 assets byte for byte, and the 4.4 zips differ only in the source commit in
  `kktls/BUILD-INFO.txt`. The 4.3, 4.2 and 4.1 openssl zips have the same libraries; their `kktls/BUILD-INFO.txt` also
  lists the java build.
- 4.1.1: no Java layer.

## v2

Android 4.1 to 4.3 (Jelly Bean, API 16-18): native OpenSSL and the CA store. The Java TLS layer and TLS 1.3 stay
4.4 only.

### New

- `kktls-openssl-4.3-<abi>-v2.zip`, `kktls-openssl-4.2-<abi>-v2.zip`, `kktls-openssl-4.1-<abi>-v2.zip` (`armeabi-v7a`,
  `x86`): OpenSSL 1.0.1u with the same backports as 4.4, built from `android-4.3_r3`, `android-4.2.2_r1` and
  `android-4.1.2_r2`. Each installs only on its own Android version. ALPN is left out on all three, Channel ID on
  4.1/4.2 (stock struct layouts); 4.1 loses `BIO_f_zlib` (zlib TLS compression, as stock 4.2 already did).
- `kktls-cacerts-v2.zip` and `kktls-restore-v2.zip` install on Android 4.1.x to 4.4.x. On 4.1/4.2 files are labelled
  only when the kernel takes SELinux labels.
- `patches/jb/`: one OpenSSL series per Jelly Bean version, `tools/kktls-jb-openssl-build.sh` to build them,
  `tools/mkzips.sh --jb` to pack them, `tools/openssl-cve-test.sh --jb-base` for the CVE reproducers; CI builds and
  tests all three versions.

### Changed

- The 4.4 openssl zip is now `kktls-openssl-4.4-<abi>-<rel>.zip` (was `kktls-openssl-<abi>-<rel>.zip`); its contents
  are the same build.
- Installer: the device's `libcrypto` exports are checked against an allow list when the zip has one (Jelly Bean
  zips); 4.4 is unchanged.
- `tools/install-adb.sh` works with the Android 4.1 toolbox (`rm` without `-f`): one fresh work directory per zip.

### Fixed

- The installer accepted a read-only `/system` (or `/data`) when its shell was busybox running as root: busybox
  `test -w` does not ask the kernel. `/proc/mounts` now decides; such an install used to fail later and roll back.
- 4.1/4.2 kernels with SELinux but no policy refuse every label write; the CA store install is now best effort there
  instead of failing (4.3 and later unchanged).

### Unchanged

- The 4.4 payloads (`libssl.so`, `libcrypto.so`, the jars, `libjavacrypto.so`, the layer D files, the CA store) and
  helpers and NOTICE files are byte for byte those of v1 (a rebuild of this branch packed with the v1 name: every other
  zip entry equal). The zips differ from v1 only in the installer scripts (`kktls/checks.sh`, `kktls/install.sh`),
  `kktls/zip.conf` (CA store and restore: `android=4.1-4.4`), the source commit in `kktls/BUILD-INFO.txt`, and the
  release name.

## v1

First public release: Android 4.4 (KitKat) OpenSSL 1.0.1u with backports, Java TLS 1.2 (layer A), TLS 1.3 through
Conscrypt (layer D), the Mozilla CA store, recovery zips with backup and restore, CI on GitHub-hosted runners.
