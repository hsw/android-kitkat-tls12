// SPDX-License-Identifier: Apache-2.0
/*
 * Host-test stub of Conscrypt 2.6-alpha2's org.conscrypt.BaseOpenSSLSocketAdapterFactory (android/): the private final
 * field "delegate" that holds the inner OpenSSLSocketFactoryImpl, which the wrapper reads on Android 4.1-4.3. Every
 * call records "adapter:<method>" and then goes to the delegate, so a test sees whether the adapter was bypassed.
 * -Dkktlstest.mode=adapter-null leaves the field null (a shape the wrapper must refuse).
 */
package org.conscrypt;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.ssl.SSLSocketFactory;
import kktlstest.RecordingSSLSocketFactory;

public abstract class BaseOpenSSLSocketAdapterFactory extends SSLSocketFactory {
    private final OpenSSLSocketFactoryImpl delegate;

    protected BaseOpenSSLSocketAdapterFactory(OpenSSLSocketFactoryImpl delegate) {
        this.delegate = "adapter-null".equals(Conscrypt.mode()) ? null : delegate;
    }

    private SSLSocketFactory d(String call) {
        RecordingSSLSocketFactory.CALLS.add("adapter:" + call);
        return delegate;
    }

    @Override public String[] getDefaultCipherSuites() { return d("getDefaultCipherSuites").getDefaultCipherSuites(); }
    @Override public String[] getSupportedCipherSuites() {
        return d("getSupportedCipherSuites").getSupportedCipherSuites();
    }
    @Override public Socket createSocket() throws IOException { return d("createSocket").createSocket(); }
    @Override public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        return d("createSocket").createSocket(s, host, port, autoClose);
    }
    @Override public Socket createSocket(String host, int port) throws IOException {
        return d("createSocket").createSocket(host, port);
    }
    @Override public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
            throws IOException {
        return d("createSocket").createSocket(host, port, localHost, localPort);
    }
    @Override public Socket createSocket(InetAddress host, int port) throws IOException {
        return d("createSocket").createSocket(host, port);
    }
    @Override public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
            throws IOException {
        return d("createSocket").createSocket(address, port, localAddress, localPort);
    }
}
