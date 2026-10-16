# kktls-symcheck and kktls-util: static helpers for the recovery zip pre-checks and install (no nm/readelf/unzip/chcon
# guaranteed in recovery or on a stock 4.4 shell). kktls-release-build.sh copies this directory into the AOSP tree as
# device/kktls/symcheck/ and builds them per ABI with `make kktls-symcheck kktls-util`; the binaries are taken from
# PRODUCT_OUT/system/bin/ and only travel inside the zips (never installed into /system).
# SPDX-License-Identifier: Apache-2.0
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := kktls-symcheck
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := kktls-symcheck.c
LOCAL_CFLAGS := -O2 -Wall -Wextra -Werror
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_STATIC_LIBRARIES := libc
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := kktls-util
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := kktls-util.c
LOCAL_CFLAGS := -O2 -std=gnu99 -Wall -Wextra -Werror
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_STATIC_LIBRARIES := libc
include $(BUILD_EXECUTABLE)
