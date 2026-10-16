# Changelog

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
