# kktls jar patcher

The release's java zips (`kktls-java-4.4.{2,4}-<abi>-<rel>.zip`) replace `core.jar`, `core-libart.jar`,
`conscrypt.jar`, `okhttp.jar` and `libjavacrypto.so` with AOSP builds. That drops every vendor change in those jars,
so the installer allows them only on AOSP-like builds of one exact release. The jar patcher takes the device's own
jars instead, replaces only the classes the kktls series changes (and the `security.properties` entry), keeps every
other class, and writes a recovery zip for that one device (`kktls-java-patched-…`). The other zips of the release
install as before.

It runs on a PC (Linux or macOS), not on the device. Nothing on the device is changed until you flash the zip it wrote.

## Requirements

- Python 3 (standard library only), bash, and Java 8+ (`java` on PATH, or `KKTLS_JAVA=/path/to/java`).
- smali/baksmali 2.5.2 (BSD-3-Clause): `fetch-smali.sh` downloads them with `curl` on the first run from the upstream
  author's Bitbucket downloads (or from a mirror with the same file names: `SMALI_URL_BASE=<url>`) and checks the
  pinned sha256; cached in `$KKTLS_CACHE` (default `${XDG_CACHE_HOME:-~/.cache}/kktls`).
- The release's zips and `SHA256SUMS` in one directory: the java zip of the device's line and ABI (the donor of the
  replacement classes and `libjavacrypto.so`), with `--accept-oem` also `kktls-openssl-4.4-<abi>-<rel>.zip` and
  `kktls-conscrypt-<abi>-<rel>.zip`. Use the patcher of the same release: zips whose installer predates the
  java-patched kind (or `oem_ack`) are a tool error, as the device would refuse what is made from them.
- The device over `adb` (`adb` on PATH; no root needed: the files are world-readable), or a copy of its `/system`
  with its `BOOTCLASSPATH` (from `init.environ.rc`) and `build.prop`.

## Use

```
python3 kktls-jarpatch.py --adb <serial> --release-dir <dir> --out <new dir> [--accept-oem] [--report report.txt]
python3 kktls-jarpatch.py --system <system dir> --bootclasspath <BOOTCLASSPATH> --build-prop <build.prop> \
    --release-dir <dir> --out <new dir> [--accept-oem] [--report report.txt]
```

Exit 0 written, 1 refused (every reason listed: jar, class, why), 2 usage or tool error. Then flash, in this order:
the openssl zip, the CA store zip if wanted, `kktls-java-patched-<ver>-<abi>-<rel>-<fp8>.zip`, and the conscrypt zip
if wanted. On an OEM/CM build flash the `kktls-openssl-oem-…` and `kktls-conscrypt-oem-…` copies written with
`--accept-oem` instead of the release's openssl and conscrypt zips (those refuse such a build). The restore zip of the
release takes everything back.

The line follows `ro.build.version.release`: 4.4.1 and 4.4.2 use the 4.4.2 donor and set, 4.4.3 and 4.4.4 the 4.4.4
ones. The stock classes of both lines are the same; the lines differ in the donor `libjavacrypto.so`. Android 4.4
(`android-4.4_r1`, `r1.2`) is refused: it lacks upstream SSLEngine and okhttp fixes that the series builds on and that
are outside the set (the patcher would keep the old code), the same reason the release's README asks for 4.4.1 or later.

## What it checks

1. Android 4.4.1 to 4.4.4, ABI `armeabi-v7a` or `x86`, a build fingerprint; no `.odex` in `/system/{framework,app,priv-app}`
   whose jar or apk lacks `classes.dex` (odexed-and-stripped ROMs are refused, as the installer does); the four jars
   present with one `classes.dex` each (`core-libart.jar` may be missing on a Dalvik-only ROM).
2. Reference check against the set file (`sets/<line>.txt`): every class the series changes, adds or removes, every
   class the donor `libjavacrypto.so` looks up by name (`check` lines) and the `security.properties` entry must be the
   stock AOSP version, compared as normalized bytecode (`normalize.py`: debug info, comments, labels, parameter names and the JVM's spelling of float literals do not
   count; every instruction, constant, string and reference does). Verdicts: `vendor-modified`, `missing`,
   `unexpected-present`, `already-kktls` ("restore first": a kktls class, the kktls `security.properties` or the
   installer's marker is there). Any of them refuses.
3. The replacement: the device jar's classes are disassembled, the set's classes are replaced by the donor's whole
   classes, the series' removed classes are deleted, and the dex is reassembled (`smali -a 19`; id counts below 65536).
   Every class not in the set must come out with the digest it went in with. Each donor jar as a whole must give the
   set's `ours` aggregate (every class and entry, listed or not): a release dir and a set file that do not belong
   together are a tool error. A class of the device's `conscrypt.jar` that the set does not name must declare no
   native method: the donor's `libjavacrypto.so` replaces the device's and registers the stock 4.4 natives only.
4. Link check per runtime (Dalvik with `core.jar`, ART with `core-libart.jar`, `linkcheck.py`): every reference of the
   replaced classes resolves on the patched boot class path, and no reference of the boot class path, the other
   framework jars or the apps that resolved before the patch breaks (a caller of a member the series removes refuses).
   Constructors resolve in the named class only (they are not inherited). A replaced, added or check class (`check`
   lines: the classes the donor's `libjavacrypto.so` uses) that another `BOOTCLASSPATH` jar defines too refuses: an
   earlier copy is the one the runtime loads, a later one is a second implementation the series or the check does not
   cover (never loaded today, refused all the same). The same holds for a resource the set writes
   (`java/security/security.properties`, which selects the kktls default socket factory): the boot class loader
   returns the first copy on `BOOTCLASSPATH`, so another boot jar carrying it refuses, earlier or later. Every patched
   jar must be on each runtime's `BOOTCLASSPATH` (`core-libart.jar` stands for `core.jar` on ART): a jar the runtime
   does not load would not carry the fix, so a system that loads its TLS classes from other jars refuses. Stock 4.4
   names `core.jar`, `conscrypt.jar` and `okhttp.jar`.
5. The zip (`rawzip.py`): each patched jar is the device jar with `classes.dex` and `security.properties` swapped,
   every other entry copied byte for byte. Its `zip.conf` (`kind=java-patched`) carries the sha256 of every device
   jar it was made from and of `ro.build.fingerprint`: the installer installs it only on that system (and only over
   the openssl zip, with the dex check). Its `NOTICE` says that the jars are the device's own with the set's classes
   replaced, then carries the donor's notices. The zips, `manifest.json` and the report carry only the sha256 of the
   fingerprint; with `--adb`, `<out>/device/build.prop` (a copy of the device's) holds the raw one.

## Not checked

- Link check: members resolve by name and descriptor only (a private method called with invoke-direct resolves
  through the superclasses like any other method). A change of a member's static/instance kind or access
  flags, a method made final or a new abstract method in a replaced class, and the invoke kind of a reference are
  not compared (the dex reader does not decode instructions, and a vendor subclass would need a device-wide walk of
  every class hierarchy). The reference check makes the replaced classes stock on every device that passes, so this
  is a property of the series, not of the device. Measured for both shipped sets: the series makes no class or
  member final or abstract, adds no abstract method, narrows no member's access and changes no member's static kind
  (a new set must be measured again).
- `conscrypt.jar` natives are checked per class (see 3.); the device's own `libjavacrypto.so` is not read (which
  classes it registers natives for is not compared with `sets/jni-classes.txt`).
- On `--accept-oem`, the `extra` native consumers in the report are listed, not checked: reading the report is the
  check.

## OEM and CyanogenMod builds (`--accept-oem`)

The openssl and conscrypt zips refuse builds with OEM/CM `build.prop` markers (`ro.cm.version`, `ro.miui.…`, …): a
matching symbol list does not prove that vendor native code was built against the same `SSL`/`SSL_CTX` layouts. On
such a build the patcher scans `/system/{lib,bin,xbin,vendor}` and the apps' native libraries for ELF files that need
`libssl.so` or `libcrypto.so` (`nativescan.py`), writes `native-consumers.txt` (each one marked `aosp` when it is in
`aosp44-ssl-consumers.txt`, else `extra`) and refuses. Read the report: an `extra` consumer may crash or misbehave
with the new OpenSSL. With `--accept-oem` it also writes `kktls-openssl-oem-…` and `kktls-conscrypt-oem-…`: the
release zips with `oem_ack=<sha256 of the fingerprint>` in `zip.conf`, which skip the OEM/CM gate on this system only.
The java-patched zip has no OEM/CM gate: the reference check decides. A CM 11 system is refused by the reference check
today (its libcore differs from stock in classes the series changes).

## Not supported

Odexed-and-stripped ROMs (no deodex mode), Jelly Bean, Android 4.4 (4.4_r1, see above), vendor-modified classes in
the set (no method-level merge), patching on the device.

## Redistribution

A patched zip holds the device's own vendor classes: it is for that device only. Do not publish it, nor the `--out`
directory (`device/` holds the files copied from the device, `stage/jars/` the patched jars).

## Files

| File | What |
|---|---|
| `kktls-jarpatch.py` | the patcher (help: `--help`) |
| `normalize.py` | per-class normalized baksmali text and digest (the reference model) |
| `mkset.py` | makes a set file from a stock and a series build of the four jars |
| `checkset.py` | the release build's drift check: the built jars against the set's `ours` column and aggregates |
| `linkcheck.py` | dex reader and link check |
| `rawzip.py` | zip rewriter that copies untouched entries raw |
| `nativescan.py`, `aosp44-ssl-consumers.txt` | the `libssl`/`libcrypto` consumer scan and the AOSP 4.4 list |
| `fetch-smali.sh` | download and sha256 check of smali/baksmali 2.5.2 |
| `sets/4.4.2.txt`, `sets/4.4.4.txt` | the set files (stock `android-4.4.2_r2` / `android-4.4.4_r2` against the release jars) |
| `sets/jni-classes.txt` | the class names the donor `libjavacrypto.so` looks up (`mkset.py --jni`) |

In the repository only: `selftest.sh` (the patcher end to end on fixture systems assembled from the smali sources in
`tests/fixtures/`, one run per refusal path), the unit tests (`python3 -I -m unittest discover tools/jarpatch/tests`)
and `fetch-smali.sh --selftest` (the download and cache logic, offline). All run in CI. The release build's `check`
step runs `checkset.py` on the jars it built and fails on any difference, also in a class the set does not list (the
`ours` aggregate); a series change of the four jars therefore needs a new set: a stock build of the tag and
`mkset.py` (see its help).
