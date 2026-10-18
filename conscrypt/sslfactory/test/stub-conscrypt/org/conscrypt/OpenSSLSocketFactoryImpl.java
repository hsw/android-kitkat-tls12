// SPDX-License-Identifier: Apache-2.0
/*
 * Host-test stub of Conscrypt's own org.conscrypt.OpenSSLSocketFactoryImpl, the KitKat adapter's inner factory: a
 * recording factory with the origin "conscrypt".
 */
package org.conscrypt;

import kktlstest.RecordingSSLSocketFactory;

public final class OpenSSLSocketFactoryImpl extends RecordingSSLSocketFactory {
    OpenSSLSocketFactoryImpl() {
        super("conscrypt");
    }
}
