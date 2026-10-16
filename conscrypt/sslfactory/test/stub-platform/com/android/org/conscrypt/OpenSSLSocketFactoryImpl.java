// SPDX-License-Identifier: Apache-2.0
/*
 * Host-test stub (Mac JDK only) of the 4.4 platform class com.android.org.conscrypt.OpenSSLSocketFactoryImpl, the
 * layer-A default factory: public no-arg constructor, as in libcore crypto/.../OpenSSLSocketFactoryImpl.java:30.
 * -Dkktlstest.platform=error makes the constructor throw an Error (the "neither factory is usable" case).
 */
package com.android.org.conscrypt;

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
