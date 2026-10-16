// SPDX-License-Identifier: Apache-2.0
/*
 * Host-test helper (Mac/Linux JDK only, never built into the image): an SSLSocket that records the protocol-related
 * calls made on it, so a test can see what org.conscrypt.KktlsFilteringSSLSocket passed to its delegate and that the
 * filter's own handshake guard fired before the delegate was reached. Every other SSLSocket/Socket method is a harmless
 * stub. Returned by RecordingSSLSocketFactory when returnSslSocket is set (so a factory test can see a Conscrypt socket
 * get wrapped) and used directly as the delegate in KktlsFilteringSSLSocketTest.
 */
package kktlstest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

public class RecordingSSLSocket extends SSLSocket {
    /** Every recorded call, in order, e.g. "setEnabledProtocols(TLSv1.2)", "setEnabledProtocols()", "startHandshake". */
    public final List<String> events = Collections.synchronizedList(new ArrayList<String>());
    /** The array last passed to setEnabledProtocols (null if it was null); what getEnabledProtocols returns. */
    public String[] enabledProtocols = new String[0];
    private String[] enabledCipherSuites = new String[0];
    private boolean clientMode = true;
    private boolean needClientAuth;
    private boolean wantClientAuth;
    private boolean enableSessionCreation = true;
    /** The SSLParameters object last passed to setSSLParameters (identity and contents are checked by the tests). */
    public SSLParameters lastParams;
    /** When set, setEnabledProtocols and setSSLParameters reject every call (as Conscrypt rejects unknown names). */
    public boolean rejectProtocols;
    /** What the 4.4 hidden Socket.getFileDescriptor$() of this socket returns (the filter must hand this out). */
    public final FileDescriptor fd = new FileDescriptor();

    private static String join(String[] a) {
        if (a == null) {
            return "null";
        }
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < a.length; i++) {
            b.append(i == 0 ? "" : ",").append(a[i]);
        }
        return b.toString();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        events.add("setEnabledProtocols(" + join(protocols) + ")");
        if (rejectProtocols) {
            throw new IllegalArgumentException("rejected: " + join(protocols));
        }
        enabledProtocols = protocols;
    }

    @Override
    public String[] getEnabledProtocols() {
        return enabledProtocols;
    }

    @Override
    public void setSSLParameters(SSLParameters params) {
        events.add("setSSLParameters(" + join(params == null ? null : params.getProtocols()) + ")");
        if (rejectProtocols) {
            throw new IllegalArgumentException("rejected");
        }
        lastParams = params;
    }

    /** The 4.4 libcore hidden method (absent from the host JDK, so no @Override); reached by the filter by reflection. */
    public FileDescriptor getFileDescriptor$() {
        events.add("getFileDescriptor$");
        return fd;
    }

    @Override
    public void startHandshake() throws IOException {
        events.add("startHandshake");
    }

    @Override
    public InputStream getInputStream() throws IOException {
        events.add("getInputStream");
        return new ByteArrayInputStream(new byte[0]);
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        events.add("getOutputStream");
        return new ByteArrayOutputStream();
    }

    @Override
    public String[] getSupportedProtocols() {
        return new String[] {"TLSv1", "TLSv1.1", "TLSv1.2"};
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return new String[] {"TLS_RSA_WITH_AES_128_CBC_SHA"};
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return enabledCipherSuites;
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        events.add("setEnabledCipherSuites(" + join(suites) + ")");
        enabledCipherSuites = suites;
    }

    @Override
    public SSLSession getSession() {
        return null;
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
    }

    @Override
    public void setUseClientMode(boolean mode) {
        clientMode = mode;
    }

    @Override
    public boolean getUseClientMode() {
        return clientMode;
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        needClientAuth = need;
    }

    @Override
    public boolean getNeedClientAuth() {
        return needClientAuth;
    }

    @Override
    public void setWantClientAuth(boolean want) {
        wantClientAuth = want;
    }

    @Override
    public boolean getWantClientAuth() {
        return wantClientAuth;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        enableSessionCreation = flag;
    }

    @Override
    public boolean getEnableSessionCreation() {
        return enableSessionCreation;
    }

    @Override
    public void close() throws IOException {
        events.add("close");
    }
}
