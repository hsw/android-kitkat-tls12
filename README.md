# android-kitkat-tls12

TLS 1.2 by default, optional TLS 1.3, and a current CA store for **Android 4.4 KitKat** (API 19) on AOSP-based
builds. Patches against the AOSP 4.4 sources, the scripts to build them, and recovery zips that install the built
files into `/system`, with a backup and a restore zip.

**Android 4.1 to 4.3** (Jelly Bean, API 16-18) get the native OpenSSL 1.0.1u and the CA store: native code that links
the system `libssl` (WebKit's network stack in the Browser and WebView, `openssl`-based daemons and apps) can speak
TLS 1.2 with current ciphers. The Java TLS layer and TLS 1.3 are **4.4 only**: on Jelly Bean, Java apps
(`HttpsURLConnection`, `SSLSocket`) keep the stock protocol list (`SSLv3, TLSv1`) and only gain the new CA store.

### Which zip for which Android version

| Android | OpenSSL 1.0.1u | CA store | Java TLS 1.2 (layer A) | TLS 1.3 (layer D) |
|---|---|---|---|---|
| 4.4.x | `kktls-openssl-4.4-<abi>` | `kktls-cacerts` | `kktls-java-4.4.2-<abi>` / `kktls-java-4.4.4-<abi>` (exact release) | `kktls-conscrypt-<abi>` |
| 4.3.x | `kktls-openssl-4.3-<abi>` | `kktls-cacerts` | no | no |
| 4.2.x | `kktls-openssl-4.2-<abi>` | `kktls-cacerts` | no | no |
| 4.1.x | `kktls-openssl-4.1-<abi>` | `kktls-cacerts` | no | no |

`<abi>` is `armeabi-v7a` or `x86`; `kktls-restore` undoes any of them. Each openssl zip is built from the AOSP tree of
its Android version and installs only there.

Stock Android 4.4 offers `SSLv3, TLSv1` by default, puts `SSL_RSA_WITH_RC4_128_MD5` first in a 35-suite list, has no
AES-GCM, falls back to SSLv3 without SNI, and ships OpenSSL 1.0.1e and a 2013 CA store. TLS 1.2-only servers,
SNI-only hosts and Let's Encrypt chains fail from Java apps.

OpenSSL 1.0.1u is past its end of life. Read [SECURITY.md](SECURITY.md) before you install or ship this.

## What you get

| Part | What it changes | Files on the device |
|---|---|---|
| **Layer A: OpenSSL** | OpenSSL 1.0.1u with post-EOL security backports, replacing 1.0.1e | `/system/lib/libssl.so`, `libcrypto.so` |
| **Layer A: Java TLS** | libcore, Conscrypt-in-libcore and okhttp backports: TLS 1.1/1.2 enabled by default, 13 default suites (ECDHE first, AES-GCM, no RC4/3DES/DES/EXPORT/MD5/DHE/static ECDH), SNI on every client path, `TLS_FALLBACK_SCSV` fallback over TLSv1 instead of SSLv3, stricter wildcard matching, intermediate CA cache fixes | `/system/framework/{core,core-libart,conscrypt,okhttp}.jar`, `/system/lib/libjavacrypto.so` |
| **Layer D: TLS 1.3** | Standalone Conscrypt 2.6-alpha2 (BoringSSL inside) behind the default `SSLSocketFactory`: TLS 1.0–1.3, ChaCha20-Poly1305, X25519, no SSLv3 | `/system/framework/kktls-conscrypt.jar`, `kktls-sslfilter.jar`, `/system/lib/libkktls_conscrypt_jni.so` |
| **CA store** | The Mozilla root store (121 roots as of 2026-09) in the Android 4.x format, replacing the 2013 directory wholesale | `/system/etc/security/cacerts/` |

Layer A needs no other change: the jars keep their class names and public API. Apps that already enable TLS 1.2 keep
working.

### Layer D in detail

- Layer D is three files in `/system`, none of them on the boot class path, and no ramdisk change. A small class in
  `core.jar` (`io.github.hsw.kktls.KktlsDefaultSSLSocketFactory`, hidden API) is the default `SSLSocketFactory`. When
  `kktls-conscrypt.jar` exists, it loads the two jars and the `.so` in a per-process class loader and uses Conscrypt.
  When the files are absent or fail to load, the platform factory is used. A failure is logged once per process
  (tag `KktlsSslFactory`).
- Scope: sockets of the default factory, i.e. `SSLSocketFactory.getDefault()`, `HttpsURLConnection` and Apache
  `DefaultHttpClient`. `SSLContext.getDefault()`, `SSLContext.getInstance("TLS")`, `SSLCertificateSocketFactory`,
  server sockets and `SSLEngine` stay on layer A. Apps that bundle their own Conscrypt are not affected.
- Behaviour changes on those sockets: SSLv3 is gone even when an app asks for it, `setEnabledCipherSuites` throws for
  RC4/DES/EXPORT/DHE/static-ECDH names, and a TLS 1.3 ClientHello may hit an intolerant middlebox (okhttp retries over
  TLSv1; Apache HTTP and plain sockets do not).
- **Kill switch:** with the files installed, layer D is on. The system property `persist.kktls.conscrypt` set to exactly
  `0` turns it off; any other value, or no value, lets the files decide. The property is read once per process:
  ```
  adb root
  adb shell setprop persist.kktls.conscrypt 0
  adb shell sync
  adb reboot
  ```
  Or remove layer D with the restore zip.

### Compatibility for apps

- SSLv3 and weak suites are off by default. A server that accepts only SSLv3, RC4, 3DES or a weak DH group fails. On
  layer A an app can still enable them with `setEnabledProtocols`/`setEnabledCipherSuites`.
- TLS server sockets no longer accept SSLv3 clients. A server key that is an EC key on an RSA-signed certificate has no
  default suite any more (stock served it only with the dropped static ECDH suites).
- `SSLEngine` (the Harmony engine) is unchanged: TLSv1 at most, no GCM, no SNI.
- The 4.4 WebView (Chromium 30) has its own TLS stack and is not changed by this project.

## Requirements

- **AOSP-based Android 4.4.x** (4.1.x to 4.3.x: the openssl and CA store zips only), 32-bit, ABI `armeabi-v7a` or
  `x86`. Builds of other ROMs are refused by the installer: CyanogenMod and its derivatives, and vendor ROMs that carry vendor properties (MIUI, EMUI, Samsung, HTC,
  Sony, LG, MediaTek and others; the list is in `installer/checks.sh`). Vendors often change the Java and OpenSSL
  sources; the jars built from AOSP would not match, and a matching symbol list does not prove that structs and
  `#define` values match what a vendor's own native code was compiled against.
- ARMv6 devices (`armeabi`) are refused. MIPS is source only: no binaries.
- The java zip must match the device's `ro.build.version.release` exactly: `kktls-java-4.4.2-*` for 4.4.2,
  `kktls-java-4.4.4-*` for 4.4.4. Other 4.4.x releases have no java zip; build from source (below). The OpenSSL zip
  `kktls-openssl-4.N-*` installs on any 4.N.x that passes the checks.
- The CA store zip (and the restore zip) install on **Android 4.1 to 4.4**: 4.1 to 4.3 (Jelly Bean, API 16-18) read
  the same `/system/etc/security/cacerts/<hash>.0` format. The java and conscrypt zips are 4.4 only. On 4.1/4.2 the
  installed files are labelled `system_file` only when the kernel takes labels: a kernel without SELinux, or one with SELinux but no
  policy loaded (AOSP 4.1/4.2 userspace loads none), gets no label and the install goes on. From 4.3 on they are
  labelled as on 4.4, and a failed label write fails the install.
- A custom recovery (TWRP, CWM) for the recovery zips, or `adb root` (eng/userdebug builds, emulator images) for the
  adb installer.

## Release zips

Each release has these zips and a `SHA256SUMS` file:

| Zip | Contents | Checks before anything is written |
|---|---|---|
| `kktls-openssl-4.4-<abi>-<rel>.zip` | `libssl.so`, `libcrypto.so` | Android 4.4.x; AOSP-like; ABI; every symbol the device's `libssl`/`libcrypto` exports is exported by ours (except 32 internal `libssl` symbols that nothing in AOSP 4.4 imports) |
| `kktls-openssl-4.3-<abi>-<rel>.zip`, `-4.2-`, `-4.1-` | the same, built from `android-4.3_r3`, `android-4.2.2_r1`, `android-4.1.2_r2` | Android 4.3.x, 4.2.x resp. 4.1.x; the same checks with the allow lists of that version (`patches/jb/<ver>/allow-missing-*.txt`: internal symbols only, plus `BIO_f_zlib` on 4.1, see below) |
| `kktls-cacerts-<rel>.zip` | the CA store | Android 4.1.x to 4.4.x |
| `kktls-java-<ver>-<abi>-<rel>.zip` | the four jars and `libjavacrypto.so` | release equals `<ver>`; AOSP-like; ABI; the openssl zip is installed; dex check |
| `kktls-conscrypt-<abi>-<rel>.zip` | layer D | AOSP-like; ABI; the java zip of the same release is installed |
| `kktls-restore-<rel>.zip` | none | a backup exists; every backup has an intact copy and was taken on this ROM |

- **Jelly Bean (4.1 to 4.3):** the openssl zip replaces 1.0.1c (4.1, 4.2) or 1.0.1e (4.3). The stock Java layer
  keeps working on it unchanged (its `SSL_MODE_HANDSHAKE_CUTTHROUGH` bit means something else in 1.0.1u, so False
  Start is off, as with the stock Java layer on 4.4). ALPN and, on 4.1/4.2, Channel ID are left out so that the
  `SSL`/`SSL_CTX` layouts stay those of the stock library. Stock 4.1 built `libcrypto` with zlib (TLS compression,
  CRIME); like stock 4.2 this build does not, so `BIO_f_zlib` is gone: nothing in AOSP 4.1 imports it, but a
  vendor app that does would fail to load.
- **Order:** openssl, then java, then conscrypt. The CA store can go at any time. The java zip needs the openssl zip
  because the Java side sets OpenSSL 1.0.1u `SSL_MODE` bits that mean something else in a stock 1.0.1e.
- **Dex check:** replacing `core.jar` makes every other pre-optimised `.odex` stale, and Dalvik regenerates them from
  the `classes.dex` inside each jar or apk. The java zip refuses when any jar or apk in `/system/framework`,
  `/system/app` or `/system/priv-app` has an `.odex` but no `classes.dex`: such a device would not boot.
- **What install does:** mounts `/system` and `/data`, runs all checks and lists every failure, checks that `/system`
  and `/data` have room for the new files and the backup (else it refuses before writing anything), backs up the files
  it will replace to `/data/kktls-backup/<n>-<time>/` and copies the backup to `/sdcard/kktls-backup/` (a factory reset
  wipes `/data` but not `/system`; without room on `/sdcard` the install goes on with a warning and one copy). The
  backup manifest records the build fingerprint and a SHA-256 of each saved file (computed by the zip's own helper,
  so a recovery without `sha256sum` works). The install then copies the files with owner root, mode 0644 and the SELinux label
  `u:object_r:system_file:s0`, and writes a marker under `/system/etc/kktls/`. The java zip also removes the `.odex`
  of the replaced jars and wipes `/data/dalvik-cache`. If copying fails, the installer rolls back from the fresh
  backup. Backups taken on another ROM (the build fingerprint changed: a ROM update or reflash) are renamed to
  `stale-<n>-<time>` and never restored.
- **The first boot after the java zip is long:** every app and jar is optimised again (about two minutes on the
  emulator, longer on slow devices). On ART, `boot.art` is regenerated too.
- **Restore:** `kktls-restore-<rel>.zip` collects the backups of `/data` and `/sdcard` and applies every one, newest
  first, so the state before the first kktls zip comes back (also when a factory reset wiped the older backups in
  `/data` and a kktls zip was installed again). Each backup comes from a copy whose files match the recorded SHA-256
  (`/data` first, else `/sdcard`). Before writing anything the restore refuses when a backup has no intact copy, or
  when a backup was taken on another ROM (its build fingerprint differs from the running one: the ROM was updated or
  reflashed and the backup would put old files over it; installing any kktls zip retires such backups). It removes
  the layer D files and the markers, wipes `/data/dalvik-cache` and renames the applied backups to `done-<n>-<time>`.
- Every zip carries a `NOTICE` with the licences of its contents.

### Install with a recovery

Check `SHA256SUMS`, copy the zips to the device and flash them in the order above from TWRP or CWM, then reboot.

### Install over adb

For emulators and eng/userdebug builds (needs `adb root`):

```
tools/install-adb.sh [-s SERIAL] kktls-openssl-4.4-armeabi-v7a-v2.zip kktls-cacerts-v2.zip \
    kktls-java-4.4.2-armeabi-v7a-v2.zip kktls-conscrypt-armeabi-v7a-v2.zip
tools/install-adb.sh [-s SERIAL] kktls-openssl-4.2-armeabi-v7a-v2.zip kktls-cacerts-v2.zip   # Android 4.2.x
tools/install-adb.sh [-s SERIAL] --restore kktls-restore-v2.zip
```

- It runs the same checks and install code as the recovery zip, and stops at the first refusal.
- A stock 4.4 shell lacks `sed`, `awk`, `find` and other tools the installer uses. The script downloads the static
  busybox 1.31.0 for the device's ABI from busybox.net (sha256-pinned), pushes it for the run and deletes it
  afterwards; `--busybox FILE` uses your own. busybox is GPL-2.0 and is not part of this repository or the zips.
- It stops the Android framework before the first zip and reboots at the end (`--no-reboot` leaves that to you).
- On an enforcing SELinux device it runs `setenforce 0` for the duration of the run and `setenforce 1` at the end:
  the 4.4 policy does not let the root shell relabel files to `system_file`.

## Tested

| Target | How | Result |
|---|---|---|
| Android SDK system image 4.4.2 ARM (`KK`, eng, odexed, SELinux enforcing) | emulator, `install-adb.sh` | all zips install; matrix of 25 TLS test servers as wanted (stock: 20 not as wanted); TLS 1.3 with layer D; restore gives the stock files back byte for byte |
| Android SDK system image 4.4.2 x86 (eng, SELinux disabled) | emulator, `install-adb.sh` | same |
| AOSP `android-4.4.4_r2` `aosp_arm-eng` build | emulator, `install-adb.sh` | same, with the 4.4.4 java zip |
| Refusals on the 4.4.2 ARM image: java before openssl, conscrypt before java, a CM marker in `build.prop`, an odexed apk without `classes.dex` | emulator | refused, device unchanged |
| Android SDK system images 4.1.2, 4.2.2, 4.3.1 ARM (and 4.4.2 again), CA store and restore zips | emulator, `install-adb.sh` | install, reboot and restore; all 121 roots parse and their self-signatures verify on each release's providers (RSA-4096, P-384, SHA-384 included); real server chains to 7 roots the stock stores lack (ISRG Root X1 and X2, GTS Root R4, DigiCert Global Root G2, USERTrust ECC, Sectigo R46, Amazon Root CA 1) are trusted after the install and not before; the stock roots that are not in the new set are no longer trusted; restore gives the stock directory back byte for byte |
| Android SDK system images 4.1.2, 4.2.2, 4.3.1 ARM, openssl zip of that version + CA store zip | emulator, `install-adb.sh`, cold boot | install, boot and restore (libraries back to stock byte for byte); no crash in dropbox; native `openssl s_client` on the system libraries: TLS 1.2 `ECDHE-ECDSA-AES128-GCM-SHA256`, chain verified against the installed store; the Browser (WebKit, system `libssl`) loads https://www.howsmyssl.com/ (which the stock CA store cannot verify) and https://www.google.com/; Java `HttpsURLConnection` reaches both with the stock protocol list (TLSv1) |
| Jelly Bean OpenSSL builds, ARM and x86 | stock libraries of the same AOSP tree and of the SDK images | no public export removed; every system binary and library that imports `libssl`/`libcrypto` resolves; public struct offsets unchanged (except members the older version lacks) |
| The recovery path (`update-binary`), 4.4.4 x86 java zip | host tests against fake `/system` trees, plus a real SDK 4.4.2 `/system` | pass |

**Not tested yet:** a real TWRP or CWM recovery (only host tests run `update-binary`); 4.4.4 on x86 in an emulator;
ART (all runs used Dalvik); real hardware other than the device below; Android 4.4.0, 4.4.1 and 4.4.3; Jelly Bean
on x86 emulators and on real hardware (only host tests run the x86 zips against the stock x86 libraries). Reports
welcome.

## Build from source

The patches apply to every KitKat tag (`android-4.4_r1` to `android-4.4.4_r2`). Use 4.4.1 or later: 4.4_r1 lacks
upstream SSLEngine and okhttp fixes that the series does not carry.

### 1. OpenSSL import

`patches/external_openssl/0002` is the generated output of AOSP's `import_openssl.sh` for the recipe in 0001. To
check or regenerate it:

```
tools/fetch-openssl.sh --out dl      # openssl-1.0.1u.tar.gz from openssl.org, sha256-pinned
tools/mkimport.sh RECIPE_DIR         # Docker; RECIPE_DIR = external/openssl with 0001 applied
```

`mkimport.sh` clones AOSP `external/openssl` at `dd1da36`, runs `import_openssl.sh` inside a container and prints
the diff size; see its header for the comparison with 0002.

### 2. Apply

On a synced AOSP 4.4 tree (a full tree, or the project list in `tools/targets.txt`):

1. On 4.4.0 to 4.4.3 only: `external/openssl` lacks `dd1da36` (the Early CCS fix, the only `external/openssl` change
   in KitKat). Cherry-pick it from `android-4.4.4_r2`.
2. `git am` in `external/openssl`: `patches/external_openssl/*.patch`.
3. `git am` in `libcore`: `patches/libcore/*.patch`. On 4.4.3 and later, one hunk of 0012 conflicts: a test file,
   `SSLSocketTest.java`, already imports `java.net.InetAddress`. Keep the existing import and add the rest.
4. `git am` in `external/okhttp`: `patches/external_okhttp/*.patch`.

### 3. Build

Use the usual AOSP 4.4 build host: 64-bit Linux, Ubuntu 14.04-era toolchain, JDK 6. AOSP 4.4 accepts only Oracle
JDK 6 out of the box; `patches/build/0001-allow-openjdk6.patch` lets it use OpenJDK 6.

```
. build/envsetup.sh
lunch aosp_arm-user        # or aosp_x86-user
make WITH_DEXPREOPT=false libcrypto libssl libjavacrypto core core-libart conscrypt okhttp
```

`WITH_DEXPREOPT=false` keeps `classes.dex` in every jar; the java zip replaces jars on devices whose other `.odex`
files then get re-optimised.

Layer D is built from the published `org.conscrypt:conscrypt-android:2.6-alpha2` aar (Maven Central, sha256-pinned):
`conscrypt/mkstage.py` converts it into a dex jar and renames the JNI library, then `conscrypt/Android.mk` installs the
staged files with the SSLv3 filter module `kktls-sslfilter`. See `conscrypt/README.md`.

`tools/kktls-release-build.sh` runs all of this in Docker for `android-4.4.2_r2` and `android-4.4.4_r2`, for both
ABIs, and runs the checks: an ABI comparison of our OpenSSL against the stock libraries of the same tag, the symbol
helper, and the release file checker. The AOSP-built jars are rewritten with sorted entries and a fixed time
(`tools/zipnorm.py`; members and compressed data unchanged), so two builds of the same commit give byte-identical
release files. `tools/mkzips.sh` packs its output into the release zips; the same inputs give byte-identical zips.

### Jelly Bean (4.1 to 4.3) OpenSSL

`patches/jb/<ver>/external_openssl/` holds one series per Android version, made the same way as the 4.4 one (0001 the
recipe, 0002 the `import_openssl.sh` output of that version's own script on its `external/openssl`): the 4.4 recipe
without ALPN, and on 4.1/4.2 without Channel ID, with the 4.3 build files. `patches/jb/targets.txt` pins the tag, lunch
targets and partial-sync project list of each version.

```
tools/kktls-jb-openssl-build.sh --work WORK --bases "4.3 4.2 4.1" all    # Docker; steps sync stock apply build collect check
tools/mkzips.sh --in WORK44/out/kktls --jb WORK/out/kktls-jb ...           # the JB openssl zips next to the 4.4 ones
```

It checks the exports against the stock libraries of the same tree (`openssl-abi-check.py`, `kktls-symcheck` with the
allow lists). The zips take the static helpers from the 4.4 build. `tools/openssl-cve-test.sh --jb-base <ver>` runs the
CVE reproducers on a Jelly Bean recipe.

CI: `.github/workflows/` runs the CVE harness (`cve-harness.yml`), the host tests and this build with the zips
(`build.yml`, in the image of `docker/Dockerfile.build`) on GitHub-hosted runners; a tag `vN` builds the zips again
and attaches them to the release of that tag (`release.yml`).

### 4. Tests

- `tools/openssl-cve-test.sh`: builds OpenSSL in Docker for host, x86, ARM and MIPS, with and without assembler, and
  runs reproducers for the backported CVEs (a FAIL on unpatched 1.0.1u, a PASS with the patches); `--jb-base <ver>`
  for a Jelly Bean series.
- `tools/openssl-abi-check.sh`: exported symbols, their users and public struct layouts against the stock OpenSSL.
- `tools/check_tls_lists.py`: protocol and cipher suite lists in the Java patches.
- `tools/tls-probe.sh`: a probe app for a device or emulator (`dump`, `hello`, `matrix` against badssl.com and
  Let's Encrypt hosts).
- `installer/test/run-tests.sh` and `symcheck/test.sh`: the installer and the symbol helper on fake `/system` trees.

### CA store

`cacerts/make-cacerts.sh cacert.pem cacert.pem.sha256 OUTDIR [now-epoch]` builds the directory from the Mozilla
bundle that curl publishes (`https://curl.se/ca/cacert.pem`): it drops expired and non-CA certificates and names
each file by `openssl x509 -subject_hash_old`, the hash Android 4.x looks up. With the same bundle and `now-epoch`
the output is byte-identical.

## Used on the ONYX BOOX Robinson Crusoe 2

This project started as part of an Android 4.4 port for the ONYX BOOX Robinson Crusoe 2 e-reader (RK3026,
Cortex-A9), where the series runs with layer A and layer D. Related public repositories:

- [onyx-rc2-ebc](https://github.com/hsw/onyx-rc2-ebc): the E-Ink display controller of that device
- [onyx-rc2-waveform](https://github.com/hsw/onyx-rc2-waveform): its panel waveform
- [onyx-rc2-hardware](https://github.com/hsw/onyx-rc2-hardware): hardware notes and boot tools

## Licence

Own code and patches: Apache-2.0 ([LICENSE](LICENSE)). The patched projects keep their licences; see
[NOTICE](NOTICE).
