# libkktls_compat.so: the bionic functions the Conscrypt 2.6-alpha2 JNI library imports and a Jelly Bean base lacks
# (kktls_compat.c). Built in the base's own AOSP tree by tools/kktls-jb-openssl-build.sh (device/kktls/conscrypt/compat/),
# so it uses that base's bionic headers and toolchain. Each base and ABI exports exactly what its libc lacks
# (= check_prebuilt.py JB_MISSING, checked after the build), never a function its libc has:
#   PLATFORM_SDK_VERSION 16 (4.1.x): the fortify functions; ARM also getauxval
#   PLATFORM_SDK_VERSION 17 (4.2.x): ARM getauxval; x86 nothing (no module)
#   other: nothing (no module)
# kktls-compat-probe: a device test of the library (test/kktls_compat_probe.c), not a release file.
# SPDX-License-Identifier: Apache-2.0
LOCAL_PATH := $(call my-dir)

kktls_compat_cflags :=
ifeq ($(PLATFORM_SDK_VERSION),16)
kktls_compat_cflags += -DKKTLS_COMPAT_FORTIFY
ifeq ($(TARGET_ARCH),arm)
kktls_compat_cflags += -DKKTLS_COMPAT_GETAUXVAL
endif
endif
ifeq ($(PLATFORM_SDK_VERSION),17)
ifeq ($(TARGET_ARCH),arm)
kktls_compat_cflags += -DKKTLS_COMPAT_GETAUXVAL
endif
endif

ifneq ($(strip $(kktls_compat_cflags)),)
include $(CLEAR_VARS)
LOCAL_MODULE := libkktls_compat
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := kktls_compat.c
LOCAL_CFLAGS := $(kktls_compat_cflags) -fvisibility=hidden -U_FORTIFY_SOURCE -Wall -Werror
LOCAL_SYSTEM_SHARED_LIBRARIES := libc
LOCAL_SHARED_LIBRARIES := liblog
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := kktls-compat-probe
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := test/kktls_compat_probe.c
LOCAL_CFLAGS := -U_FORTIFY_SOURCE -Wall -Werror
LOCAL_SHARED_LIBRARIES := libdl
include $(BUILD_EXECUTABLE)
endif
kktls_compat_cflags :=
