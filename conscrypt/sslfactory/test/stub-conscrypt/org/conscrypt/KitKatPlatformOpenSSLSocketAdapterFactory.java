// SPDX-License-Identifier: Apache-2.0
/*
 * Host-test stub of Conscrypt 2.6-alpha2's org.conscrypt.KitKatPlatformOpenSSLSocketAdapterFactory, what its
 * SSLContext returns for SDK_INT < 22 (-Dkktlstest.mode=adapter or adapter-null).
 */
package org.conscrypt;

public class KitKatPlatformOpenSSLSocketAdapterFactory extends BaseOpenSSLSocketAdapterFactory {
    public KitKatPlatformOpenSSLSocketAdapterFactory(OpenSSLSocketFactoryImpl delegate) {
        super(delegate);
    }
}
