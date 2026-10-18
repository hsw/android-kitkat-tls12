// SPDX-License-Identifier: Apache-2.0
/*
 * Host-test stub of the Android 4.4 platform class com.android.org.conscrypt.OpenSSLSocketImpl, the superclass of
 * Conscrypt's KitKat adapter sockets. Only its presence matters: with it (4.4) the wrapper keeps Conscrypt's KitKat
 * adapter factory, without it (4.1-4.3) the wrapper takes the adapter's inner factory.
 */
package com.android.org.conscrypt;

public abstract class OpenSSLSocketImpl {
    private OpenSSLSocketImpl() {}
}
