# Layer D: standalone Conscrypt 2.6-alpha2 for Android 4.4

Layer D adds TLS 1.3 (and TLS 1.0–1.2 with ChaCha20-Poly1305 and X25519) to the default `SSLSocketFactory` of an
Android 4.4 system that already has layer A. It is the published `org.conscrypt:conscrypt-android:2.6-alpha2` artefact
(Maven Central; BoringSSL inside), turned into KitKat system modules:

| Module | Installed as | From |
|---|---|---|
| `kktls-conscrypt` | `/system/framework/kktls-conscrypt.jar` | the aar's `classes.jar`, JNI library name changed, dexed by d8 |
| `libkktls_conscrypt_jni` | `/system/lib/libkktls_conscrypt_jni.so` | the aar's `armeabi-v7a` or `x86` JNI library, byte-identical |
| `kktls-sslfilter` | `/system/framework/kktls-sslfilter.jar` | `sslfilter/`: drops SSLv3 and the weak suites on Conscrypt sockets |

None of them is on the boot class path and nothing changes in the ramdisk. The default factory
`io.github.hsw.kktls.KktlsDefaultSSLSocketFactory` is part of `core.jar` (libcore patch 0025). On first use it loads the
two jars and the `.so` with its own class loader when `kktls-conscrypt.jar` exists, and falls back to the platform
factory when the files are absent or fail to load. The system property `persist.kktls.conscrypt=0` turns layer D off.
See the top-level README for the scope and the behaviour changes.

## Why the JNI library is renamed

The 4.4 dynamic linker identifies a library by its basename. An app that bundles its own Conscrypt loads
`libconscrypt_jni.so`; if ours had the same name, the app would get our already loaded copy, and its `JNI_OnLoad` would
bind to the wrong class loader's classes. `rename_jni.py` changes the library name inside the jar's `NativeCrypto`
class, so the system copy loads `libkktls_conscrypt_jni.so` and both can coexist.

## Building the stage

The 2.6-alpha2 classes are Java 8 class files that the 4.4 `dx` refuses, so the jar is dexed outside the tree:

```
python3 -I conscrypt/mkstage.py conscrypt-android-2.6-alpha2.aar STAGE/2.6-alpha2 \
    --java-libs <built 4.4 tree>/out/target/common/obj/JAVA_LIBRARIES --d8 <build-tools 37.0.0>/d8
python3 -I conscrypt/check_prebuilt.py --stage STAGE/2.6-alpha2
```

- `mkstage.py` checks the aar and every intermediate against `SHA256SUMS`, runs `rename_jni.py`, then
  `d8 --release --min-api 19`, and writes `kktls-conscrypt.dex.jar`, `libkktls_conscrypt_jni.so` and
  `x86/libkktls_conscrypt_jni.so`. d8 from Android build-tools 37.0.0 gives the pinned bytes; another d8 version fails
  the pin with both hashes shown.
- `check_prebuilt.py --stage` checks the pins, the dex format, the ELF headers of both ABIs, that the `.so` imports only
  symbols the 4.4 bionic exports (`bionic44-exports.txt`, `bionic44-exports-x86.txt`), and the `NOTICE`.
- `Android.mk` installs the stage files byte-identical (sha256-checked in the build recipe). The stage directory is
  `KKTLS_CONSCRYPT_STAGE` (default `../stock/conscrypt/2.6-alpha2/` beside the source tree).

`tools/kktls-release-build.sh` does all of this; see its header.

## Checks and tests

- `python3 -I conscrypt/apicheck.py --selftest`: the Java API the dex references, against what Android 4.4 provides
  (`apicheck-allow.txt` lists the reviewed exceptions).
- `python3 -I conscrypt/rename_jni.py --selftest`, `python3 -I conscrypt/check_prebuilt.py --selftest AAR`.
- `conscrypt/sslfactory/test/run-host-tests.sh`: the default factory and the SSLv3 filter on a host JVM with stubs
  (files present, absent, broken; the kill switch).

## Licences

`NOTICE` holds the Conscrypt and BoringSSL licence texts of the pinned versions. `mknotice.sh` regenerates it from a
Conscrypt clone and the BoringSSL commit named in the aar; its sha256 is pinned in `SHA256SUMS`.
