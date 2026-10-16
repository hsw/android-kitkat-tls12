// SPDX-License-Identifier: Apache-2.0
/*
 * Host-test stub (Mac JDK only) of org.conscrypt.Conscrypt 2.6-alpha2: newProvider() and newProviderBuilder() with
 * the 2.6 ProviderBuilder (isTlsV1Deprecated(boolean), isTlsV1Enabled(boolean), build()). Both Provider paths offer
 * SSLContext "TLS". Records: newProvider() as "conscrypt:newProvider", each builder step as
 * "conscrypt:<method>(<arg>)", build() as "conscrypt:build(deprecated=<d>,enabled=<e>)" with the flags it builds
 * with. The builder's defaults are alpha2's on Android (deprecated = true, enabled = false: TLS 1.2/1.3 only);
 * like the real OpenSSLProvider, build() throws IllegalArgumentException for deprecated = false with enabled = false.
 * On the host it is loaded by the stub dalvik.system.PathClassLoader (the wrapper's own loader for
 * kktls-conscrypt.jar), never by the wrapper's loader. The 2.5.3 API shape (a builder without the TLSv1 switches) is
 * stub-conscrypt-253/. The failure mode comes from -Dkktlstest.mode (read at class init and at each call):
 *   ok    (default) a provider whose TLS context gives a recording factory with origin "conscrypt"
 *   eiie  the static initializer throws, so Class.forName() throws ExceptionInInitializerError
 *   ule   newProvider() and build() throw UnsatisfiedLinkError (no libkktls_conscrypt_jni.so)
 *   rte   newProvider() and build() throw IllegalArgumentException (any RuntimeException)
 *   nsae  the provider has no SSLContext.TLS, so SSLContext.getInstance() throws NoSuchAlgorithmException
 *   kme   SSLContext.init() throws KeyManagementException
 *   null  SSLContext.getSocketFactory() returns null
 */
package org.conscrypt;

import java.security.KeyManagementException;
import java.security.Provider;
import java.security.SecureRandom;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import kktlstest.RecordingSSLSocketFactory;

public final class Conscrypt {
    static {
        if ("eiie".equals(mode())) {
            throw new IllegalStateException("stub: Conscrypt static init fails");
        }
    }

    private Conscrypt() {}

    static String mode() {
        return System.getProperty("kktlstest.mode", "ok");
    }

    public static Provider newProvider() {
        String m = mode();
        if ("ule".equals(m)) {
            throw new UnsatisfiedLinkError("stub: no libconscrypt_jni in java.library.path");
        }
        if ("rte".equals(m)) {
            throw new IllegalArgumentException("stub: newProvider fails");
        }
        RecordingSSLSocketFactory.CALLS.add("conscrypt:newProvider");
        return new StubProvider(!"nsae".equals(m));
    }

    public static ProviderBuilder newProviderBuilder() {
        RecordingSSLSocketFactory.CALLS.add("conscrypt:newProviderBuilder");
        return new ProviderBuilder();
    }

    /** Conscrypt 2.6-alpha2's builder API; only the TLSv1 switches and build() matter to the wrapper. */
    public static class ProviderBuilder {
        private boolean deprecatedTlsV1 = true;
        private boolean enabledTlsV1 = false;

        ProviderBuilder() {}

        public ProviderBuilder setName(String name) {
            RecordingSSLSocketFactory.CALLS.add("conscrypt:setName(" + name + ")");
            return this;
        }

        public ProviderBuilder isTlsV1Deprecated(boolean deprecated) {
            RecordingSSLSocketFactory.CALLS.add("conscrypt:isTlsV1Deprecated(" + deprecated + ")");
            deprecatedTlsV1 = deprecated;
            return this;
        }

        public ProviderBuilder isTlsV1Enabled(boolean enabled) {
            RecordingSSLSocketFactory.CALLS.add("conscrypt:isTlsV1Enabled(" + enabled + ")");
            enabledTlsV1 = enabled;
            return this;
        }

        public Provider build() {
            String m = mode();
            if ("ule".equals(m)) {
                throw new UnsatisfiedLinkError("stub: no libconscrypt_jni in java.library.path");
            }
            if ("rte".equals(m)) {
                throw new IllegalArgumentException("stub: build fails");
            }
            if (!deprecatedTlsV1 && !enabledTlsV1) {
                throw new IllegalArgumentException("TLSv1 is not deprecated and cannot be disabled.");
            }
            RecordingSSLSocketFactory.CALLS.add("conscrypt:build(deprecated=" + deprecatedTlsV1 + ",enabled="
                    + enabledTlsV1 + ")");
            return new StubProvider(!"nsae".equals(m));
        }
    }

    public static final class StubProvider extends Provider {
        StubProvider(boolean withTls) {
            super("StubConscrypt", 2.6, "host-test stub of Conscrypt");
            if (withTls) {
                put("SSLContext.TLS", StubContextSpi.class.getName());
            }
        }
    }

    public static final class StubContextSpi extends SSLContextSpi {
        public StubContextSpi() {}

        @Override
        protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {
            if ("kme".equals(mode())) {
                throw new KeyManagementException("stub: init fails");
            }
            RecordingSSLSocketFactory.CALLS.add("conscrypt:init(" + km + "," + tm + "," + sr + ")");
        }

        @Override
        protected SSLSocketFactory engineGetSocketFactory() {
            return "null".equals(mode()) ? null : new RecordingSSLSocketFactory("conscrypt");
        }

        @Override
        protected SSLServerSocketFactory engineGetServerSocketFactory() {
            throw new UnsupportedOperationException();
        }

        @Override
        protected SSLEngine engineCreateSSLEngine() {
            throw new UnsupportedOperationException();
        }

        @Override
        protected SSLEngine engineCreateSSLEngine(String host, int port) {
            throw new UnsupportedOperationException();
        }

        @Override
        protected SSLSessionContext engineGetServerSessionContext() {
            throw new UnsupportedOperationException();
        }

        @Override
        protected SSLSessionContext engineGetClientSessionContext() {
            throw new UnsupportedOperationException();
        }
    }
}
