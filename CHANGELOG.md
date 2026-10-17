# Changelog

## v3 (unreleased)

Android 4.3, 4.2 and 4.1.2: the Java TLS layer (layer A) on ARM.

### New

- `kktls-java-4.3-armeabi-v7a-<rel>.zip`: `core.jar` and `libjavacore.so` built from `android-4.3_r3` with the libcore
  series of 4.4 in the Jelly Bean layout (`patches/jb/4.3/libcore/`): TLS 1.1 and 1.2 on by default, the 13 default
  suites, SNI on every client path, stricter wildcard matching, the intermediate CA fixes. `HttpsURLConnection`
  (`libcore.net.http` on 4.3, no okhttp) retries a failed handshake over TLSv1 with `TLS_FALLBACK_SCSV` instead of
  SSLv3. Installs on 4.3.x (AOSP: 4.3, 4.3.1) after the 4.3 openssl zip; the restore zip undoes it.
- `kktls-java-4.2-armeabi-v7a-<rel>.zip`: the same for `android-4.2.2_r1` (`patches/jb/4.2/libcore/`, the 4.3 series
  ported to 4.2: `int` handles in `NativeCrypto`, the 4.2 cut-through bit). Installs on 4.2.x (AOSP: 4.2, 4.2.1, 4.2.2)
  after the 4.2 openssl zip.
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

- The 4.4 zips, the CA store and the restore zip: same payload and installer. The 4.3, 4.2 and 4.1 openssl zips have
  the same libraries; their `kktls/BUILD-INFO.txt` also lists the java build.
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
