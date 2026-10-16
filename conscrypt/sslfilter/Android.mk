# Layer D: kktls-sslfilter, a tiny
# non-boot jar that holds org.conscrypt.KktlsFilteringSSLSocket, the SSLv3-filtering wrapper socket the default factory
# (io.github.hsw.kktls.KktlsDefaultSSLSocketFactory in libcore) puts around Conscrypt 2.6-alpha2 sockets so setEnabledProtocols keeps Conscrypt 2.5.3's "SSLv3"
# handling (2.6-alpha2 throws IllegalArgumentException instead of filtering). Installed to /system/framework and loaded
# by the wrapper's own Conscrypt PathClassLoader (kktls-conscrypt.jar + kktls-sslfilter.jar) when layer D is in use. It is in
# package org.conscrypt and on that loader so Tls12Probe.socketOrigin still classifies the wrapped socket as Conscrypt
# (no probe re-pin). It is NOT a boot jar and must NEVER be on BOOTCLASSPATH: a boot copy of an org.conscrypt class
# would shadow an app's own Conscrypt. A device's PRODUCT_PACKAGES lists it.
# Depends on core alone (javax.net.ssl, java.*); Java 6 source. Parsed through ../Android.mk (all-makefiles-under),
# like any makefile one level down.
# SPDX-License-Identifier: Apache-2.0
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := kktls-sslfilter
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := $(call all-java-files-under, src)
LOCAL_NO_STANDARD_LIBRARIES := true
LOCAL_JAVA_LIBRARIES := core
LOCAL_PROGUARD_ENABLED := disabled
LOCAL_NO_EMMA_INSTRUMENT := true
LOCAL_NO_EMMA_COMPILE := true
include $(BUILD_JAVA_LIBRARY)
