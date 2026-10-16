// SPDX-License-Identifier: Apache-2.0
/*
 * Host-test stub (Mac JDK only) of the org.conscrypt.Conscrypt 2.5.3 API shape: newProvider() and a ProviderBuilder
 * without the TLSv1 switches of 2.6 (isTlsV1Deprecated/isTlsV1Enabled), so a wrapper that needs them meets
 * NoSuchMethodException, as with a 2.5.3 kktls-conscrypt.jar. Records "conscrypt:newProvider",
 * "conscrypt:newProviderBuilder" and "conscrypt:build"; its Provider has no SSLContext, so a wrapper that used it
 * anyway would fail later with NoSuchAlgorithmException, not NoSuchMethodException. Served by the stub
 * dalvik.system.PathClassLoader like stub-conscrypt/.
 */
package org.conscrypt;

import java.security.Provider;
import kktlstest.RecordingSSLSocketFactory;

public final class Conscrypt {
    private Conscrypt() {}

    public static Provider newProvider() {
        RecordingSSLSocketFactory.CALLS.add("conscrypt:newProvider");
        return new Provider("StubConscrypt253", 2.5, "host-test stub of Conscrypt 2.5.3") {};
    }

    public static ProviderBuilder newProviderBuilder() {
        RecordingSSLSocketFactory.CALLS.add("conscrypt:newProviderBuilder");
        return new ProviderBuilder();
    }

    public static class ProviderBuilder {
        ProviderBuilder() {}

        public ProviderBuilder setName(String name) {
            return this;
        }

        public ProviderBuilder provideTrustManager(boolean provide) {
            return this;
        }

        public ProviderBuilder defaultTlsProtocol(String protocol) {
            return this;
        }

        public Provider build() {
            RecordingSSLSocketFactory.CALLS.add("conscrypt:build");
            return newProvider();
        }
    }
}
