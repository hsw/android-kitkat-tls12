# Layer D: standalone Conscrypt 2.6-alpha2 as KitKat modules. Optional modules; a device's PRODUCT_PACKAGES lists them
# and kktls-sslfilter (sslfilter/, included at the end of this file). None is a boot jar: the default SSLSocketFactory
# (io.github.hsw.kktls.KktlsDefaultSSLSocketFactory, part of libcore since libcore/0025) loads them with its own
# PathClassLoader when kktls-conscrypt.jar exists, so layer D is three files in /system and changes neither
# BOOTCLASSPATH nor the ramdisk.
#   kktls-conscrypt          /system/framework/kktls-conscrypt.jar: the stage's prebuilt dex jar kktls-conscrypt.dex.jar
#                          (mkstage.py: the aar's classes.jar, JNI name changed by rename_jni.py, then
#                          d8 --release --min-api 19 --lib core --lib conscrypt; classes.dex 035 + conscrypt.properties),
#                          installed byte-identical (no dx here: the alpha2 classes are major 52, which the 4.4 dx refuses)
#   libkktls_conscrypt_jni    /system/lib/libkktls_conscrypt_jni.so: the aar's armeabi-v7a JNI library (BoringSSL inside;
#                          on an x86 product the aar's x86 one, stage x86/), byte-identical, under its own basename (see rename_jni.py: the 4.4 linker dedups
#                          by basename, so an app's own libconscrypt_jni.so and ours must not share one)
#
# The stage is NOT in git. It lives beside the tree's source directory: KKTLS_CONSCRYPT_STAGE, default
# ../stock/conscrypt/2.6-alpha2/ relative to the top of the tree, built from the pinned aar by mkstage.py (README.md,
# "Building the stage"). Gates, all against the "2.6-alpha2/<file>" lines of SHA256SUMS:
#   - check_prebuilt.py --stage DIR before make;
#   - a missing stage stops the PARSE when the goals need it: a goal naming one of the two modules, or a full image goal
#     (droid, the default, systemimage, dist, otapackage, snod) of a product whose PRODUCT_PACKAGES lists them. Every other goal, and every other product (aosp_arm), only gets a warning and builds;
#   - the copy step below checks each file's sha256 in its recipe, so a wrong or missing file fails these modules.
# The stage path names the version: a version bump changes it here, in SHA256SUMS and mkstage.py.
# SPDX-License-Identifier: Apache-2.0
LOCAL_PATH := $(call my-dir)

KKTLS_CONSCRYPT_STAGE ?= $(abspath ../stock/conscrypt/2.6-alpha2/)
kktls_conscrypt_sums := $(LOCAL_PATH)/SHA256SUMS
kktls_conscrypt_dexjar_sha256 := $(shell awk '$$2 == "2.6-alpha2/kktls-conscrypt.dex.jar" {print $$1}' $(kktls_conscrypt_sums))
# the JNI library of the target ABI: ARM at the top of the stage (where every tree has it), x86 in x86/
kktls_conscrypt_so_rel := $(if $(filter x86,$(TARGET_ARCH)),x86/)libkktls_conscrypt_jni.so
kktls_conscrypt_so_sha256 := $(shell awk '$$2 == "2.6-alpha2/$(kktls_conscrypt_so_rel)" {print $$1}' $(kktls_conscrypt_sums))
ifneq ($(words $(kktls_conscrypt_dexjar_sha256) $(kktls_conscrypt_so_sha256)),2)
$(error $(LOCAL_PATH): SHA256SUMS must pin 2.6-alpha2/kktls-conscrypt.dex.jar and 2.6-alpha2/$(kktls_conscrypt_so_rel))
endif

kktls_conscrypt_src_dexjar := $(KKTLS_CONSCRYPT_STAGE)/kktls-conscrypt.dex.jar
kktls_conscrypt_src_so := $(KKTLS_CONSCRYPT_STAGE)/$(kktls_conscrypt_so_rel)
kktls_conscrypt_verified := $(call intermediates-dir-for,ETC,kktls-conscrypt-stage)
kktls_conscrypt_dexjar := $(kktls_conscrypt_verified)/kktls-conscrypt.dex.jar
kktls_conscrypt_so := $(kktls_conscrypt_verified)/libkktls_conscrypt_jni.so

# Copy one stage file into the intermediates after checking its sha256 (fresh mtime: the copy is always newer than an
# installed file of an earlier build, e.g. the 2.5.3 dx output at the same install path). Each output has its own rule
# (make 3.81 would run a two-target rule twice under -j). Rebuilt when SHA256SUMS or this file changes.
define kktls-conscrypt-stage-copy
@echo "kktls-conscrypt: $@ <- $(PRIVATE_SRC)"
$(hide) if [ ! -f "$(PRIVATE_SRC)" ]; then \
  echo "error: kktls-conscrypt: $(PRIVATE_SRC) is missing; stage it with" >&2; \
  echo "error:   conscrypt/mkstage.py (see conscrypt/README.md)" >&2; \
  exit 1; fi
$(hide) mkdir -p $(dir $@) && rm -f $@ $@.tmp
$(hide) cat "$(PRIVATE_SRC)" > $@.tmp
$(hide) if ! echo "$(PRIVATE_SHA256)  $@.tmp" | sha256sum -c --quiet - >/dev/null 2>&1; then \
  echo "error: kktls-conscrypt: sha256 of $(PRIVATE_SRC) is not $(PRIVATE_SHA256) (conscrypt/SHA256SUMS)" >&2; \
  rm -f $@.tmp; exit 1; fi
$(hide) mv $@.tmp $@
endef

# A missing stage file must reach the recipe (and its message) on every make, even when an earlier copy is still there.
kktls_conscrypt_modules := kktls-conscrypt libkktls_conscrypt_jni
kktls_conscrypt_needed := $(strip \
  $(filter $(kktls_conscrypt_modules),$(MAKECMDGOALS)) \
  $(if $(filter $(kktls_conscrypt_modules),$(PRODUCTS.$(INTERNAL_PRODUCT).PRODUCT_PACKAGES)), \
    $(if $(MAKECMDGOALS),$(filter droid systemimage dist otapackage snod,$(MAKECMDGOALS)),droid)))
ifneq ($(wildcard $(kktls_conscrypt_src_dexjar)),)
ifneq ($(wildcard $(kktls_conscrypt_src_so)),)
kktls_conscrypt_staged := true
endif
endif
ifneq ($(kktls_conscrypt_staged),true)
ifneq ($(kktls_conscrypt_needed),)
$(error kktls-conscrypt: the 2.6-alpha2 stage in $(KKTLS_CONSCRYPT_STAGE) is incomplete and the goal ($(kktls_conscrypt_needed)) needs it; stage it with conscrypt/mkstage.py, see conscrypt/README.md)
endif
$(warning kktls-conscrypt: the 2.6-alpha2 stage in $(KKTLS_CONSCRYPT_STAGE) is incomplete; kktls-conscrypt and libkktls_conscrypt_jni will fail to build)
kktls_conscrypt_dexjar_dep := FORCE
kktls_conscrypt_so_dep := FORCE
else
kktls_conscrypt_dexjar_dep := $(kktls_conscrypt_src_dexjar)
kktls_conscrypt_so_dep := $(kktls_conscrypt_src_so)
endif

$(kktls_conscrypt_dexjar): PRIVATE_SRC := $(kktls_conscrypt_src_dexjar)
$(kktls_conscrypt_dexjar): PRIVATE_SHA256 := $(kktls_conscrypt_dexjar_sha256)
$(kktls_conscrypt_dexjar): $(kktls_conscrypt_dexjar_dep) $(kktls_conscrypt_sums) $(LOCAL_PATH)/Android.mk
	$(kktls-conscrypt-stage-copy)
$(kktls_conscrypt_so): PRIVATE_SRC := $(kktls_conscrypt_src_so)
$(kktls_conscrypt_so): PRIVATE_SHA256 := $(kktls_conscrypt_so_sha256)
$(kktls_conscrypt_so): $(kktls_conscrypt_so_dep) $(kktls_conscrypt_sums) $(LOCAL_PATH)/Android.mk
	$(kktls-conscrypt-stage-copy)

# The dex jar as a prebuilt JAVA_LIBRARIES module: prebuilt.mk copies it unchanged to the install path (no dx, no
# dexpreopt: 4.4's prebuilt.mk dexpreopts only apps) and to the COMMON intermediates classes.jar/javalib.jar, which
# nothing reads: no module may list kktls-conscrypt in LOCAL_JAVA_LIBRARIES or LOCAL_STATIC_JAVA_LIBRARIES (it is dex,
# not class files). Not a boot jar: PackageManagerService dexopts it into /data/dalvik-cache at boot like every other
# /system/framework jar off BOOTCLASSPATH. Conscrypt's KitKat adapter extends the platform
# com.android.org.conscrypt.OpenSSLSocketImpl, found at run time through the boot class loader, the parent of the
# wrapper's PathClassLoader (d8 read core and conscrypt as --lib only).
include $(CLEAR_VARS)
LOCAL_MODULE := kktls-conscrypt
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := JAVA_LIBRARIES
LOCAL_MODULE_SUFFIX := $(COMMON_JAVA_PACKAGE_SUFFIX)
LOCAL_PREBUILT_MODULE_FILE := $(kktls_conscrypt_dexjar)
include $(BUILD_PREBUILT)

# The JNI library for ARM and x86 (the aar's armeabi-v7a / x86 builds: NDK r25c, NEEDED libc/libdl/libm/liblog, SysV
# .hash + GNU hash; the x86 one needs dl_iterate_phdr, which the 4.4 x86 libdl exports). MIPS: none (the aar has no MIPS). The renamed NativeCryptoJni calls System.loadLibrary("kktls_conscrypt_jni"), which fixes the file name
# libkktls_conscrypt_jni.so; the bytes are the aar's (its DT_SONAME still says libconscrypt_jni.so, which the 4.4 linker
# ignores: it names a loaded library by the basename of the path it opened). An app's own libconscrypt_jni.so therefore
# never meets ours in the linker's list. Nothing installs /system/lib/libconscrypt_jni.so (and libcore's HOST module
# libconscrypt_jni no longer shares a module name with ours).
ifneq ($(filter arm x86,$(TARGET_ARCH)),)
include $(CLEAR_VARS)
LOCAL_MODULE := libkktls_conscrypt_jni
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := SHARED_LIBRARIES
LOCAL_MODULE_SUFFIX := .so
LOCAL_PREBUILT_MODULE_FILE := $(kktls_conscrypt_so)
include $(BUILD_PREBUILT)
endif

# kktls-sslfilter (sslfilter/Android.mk). findleaves.py does not descend below a directory that has an Android.mk, so
# the makefiles one level down are included here (without this line `make kktls-sslfilter` says "No rule to make
# target", trial tree 2026-10-09 from f1da878). sslfactory/ has no makefile: its wrapper source is built as part of
# libcore (libcore/0025 carries it byte for byte; sslfactory/test/run-host-tests.sh checks that).
include $(call all-makefiles-under,$(LOCAL_PATH))
