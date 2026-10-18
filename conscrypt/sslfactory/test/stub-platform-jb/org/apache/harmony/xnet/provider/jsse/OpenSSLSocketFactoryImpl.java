// SPDX-License-Identifier: Apache-2.0
/*
 * Host-test stub of the Android 4.1-4.3 platform class org.apache.harmony.xnet.provider.jsse.OpenSSLSocketFactoryImpl,
 * the layer-A default factory of the Jelly Bean libcore (no com.android.org.conscrypt there): public no-arg
 * constructor. -Dkktlstest.platform=error makes the constructor throw an Error, as stub-platform's.
 */
package org.apache.harmony.xnet.provider.jsse;

import kktlstest.RecordingSSLSocketFactory;

public class OpenSSLSocketFactoryImpl extends RecordingSSLSocketFactory {
    public OpenSSLSocketFactoryImpl() {
        super("platform");
        if ("error".equals(System.getProperty("kktlstest.platform"))) {
            throw new LinkageError("stub: platform OpenSSLSocketFactoryImpl fails");
        }
        CALLS.add("platform:new");
    }
}
