// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (C) 2026 The android-kitkat-tls12 authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.conscrypt;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * Layer D: a thin {@link SSLSocket}
 * that wraps a Conscrypt 2.6-alpha2 socket and restores the Conscrypt 2.5.3 handling of {@code "SSLv3"} in
 * {@link #setEnabledProtocols}. 2.6-alpha2 throws {@code IllegalArgumentException: protocol SSLv3 is not supported}
 * whenever the array holds {@code "SSLv3"} (NativeCrypto.checkEnabledProtocols); 2.5.3 silently dropped {@code "SSLv3"}
 * and kept the rest, so {@code {"SSLv3"}} left no protocol enabled and the handshake failed with
 * "No enabled protocols; ...". This wrapper reproduces 2.5.3: it removes {@code "SSLv3"} before the delegate sees the
 * list, and if that empties the list it fails the handshake with the same message instead of letting the delegate
 * reject it first. TLS 1.0/1.1 are kept (re-enabled on the provider); only {@code "SSLv3"} is filtered.
 *
 * <p>The class lives in package {@code org.conscrypt} on purpose: it is installed in the non-boot jar kktls-sslfilter and
 * loaded by the wrapper's own Conscrypt PathClassLoader (kktls-conscrypt.jar + kktls-sslfilter.jar), so a socket of this
 * class is still classified as a Conscrypt socket by the TLS probe (Tls12Probe.socketOrigin: an {@code org.conscrypt.*}
 * class whose loader is the one that holds kktls-conscrypt.jar). It depends on nothing beyond {@code core}
 * ({@code javax.net.ssl}, {@code java.*}); it is <b>not</b> a Conscrypt class and must never be on the boot class path.
 * Wrapping loses the delegate's identity as {@code com.android.org.conscrypt.OpenSSLSocketImpl}, so okhttp's
 * platform-socket extensions (session tickets, ALPN; SNI survives because Conscrypt reads it from the connect host) do
 * not fire; the matrix row behaviour is unchanged for plain HTTPS. Java 6 source.
 */
public final class KktlsFilteringSSLSocket extends SSLSocket {
    static final String SSLV3 = "SSLv3";
    static final String NO_PROTOCOLS = "No enabled protocols; SSLv3 is no longer supported and was filtered from the"
            + " list";

    private final SSLSocket delegate;
    /** Set by the last {@link #setEnabledProtocols}/{@link #setSSLParameters} that removed only {@code "SSLv3"} and so
     *  left the enabled list empty; the handshake must then fail as 2.5.3 did, not as 2.6-alpha2 would. */
    private boolean emptiedBySslv3;

    public KktlsFilteringSSLSocket(SSLSocket delegate) {
        if (delegate == null) {
            throw new NullPointerException("delegate");
        }
        this.delegate = delegate;
    }

    /** {@code protocols} without any {@code "SSLv3"} entry. {@code null} is returned unchanged for the caller to pass
     *  on (the delegate throws, as before). */
    static String[] filterSslv3(String[] protocols) {
        if (protocols == null) {
            return null;
        }
        List<String> keep = new ArrayList<String>(protocols.length);
        for (int i = 0; i < protocols.length; i++) {
            if (!SSLV3.equals(protocols[i])) {
                keep.add(protocols[i]);
            }
        }
        return keep.toArray(new String[keep.size()]);
    }

    /** True when {@link #filterSslv3} turned a non-empty list into an empty one (it held only {@code "SSLv3"}). */
    static boolean emptiedBy(String[] protocols, String[] filtered) {
        return protocols != null && protocols.length > 0 && filtered.length == 0;
    }

    private void failIfEmptied() throws SSLHandshakeException {
        if (emptiedBySslv3) {
            throw new SSLHandshakeException(NO_PROTOCOLS);
        }
    }

    // ---- the behaviour this wrapper exists for -----------------------------------------------------------------

    @Override
    public void setEnabledProtocols(String[] protocols) {
        String[] filtered = filterSslv3(protocols);
        delegate.setEnabledProtocols(filtered);
        // only after the delegate accepted the list: a rejected call leaves the previous state
        emptiedBySslv3 = emptiedBy(protocols, filtered);
    }

    @Override
    public String[] getEnabledProtocols() {
        return delegate.getEnabledProtocols();
    }

    @Override
    public void setSSLParameters(SSLParameters params) {
        if (params != null && params.getProtocols() != null) {
            // Filter SSLv3 without mutating the caller's object (2.5.3 filtered internally). Copy the
            // fields SSLParameters carries on API 19: cipher suites, protocols, and the client-auth flag.
            String[] protocols = params.getProtocols();
            String[] filtered = filterSslv3(protocols);
            SSLParameters copy = new SSLParameters(params.getCipherSuites(), filtered);
            if (params.getNeedClientAuth()) {
                copy.setNeedClientAuth(true);
            } else if (params.getWantClientAuth()) {
                copy.setWantClientAuth(true);
            }
            delegate.setSSLParameters(copy);
            emptiedBySslv3 = emptiedBy(protocols, filtered);
        } else {
            delegate.setSSLParameters(params);
        }
    }

    @Override
    public void startHandshake() throws IOException {
        failIfEmptied();
        delegate.startHandshake();
    }

    @Override
    public InputStream getInputStream() throws IOException {
        failIfEmptied();
        return delegate.getInputStream();
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        failIfEmptied();
        return delegate.getOutputStream();
    }

    // ---- plain delegation (every other SSLSocket + Socket method of the 4.4 API) --------------------------------

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return delegate.getEnabledCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        delegate.setEnabledCipherSuites(suites);
    }

    @Override
    public String[] getSupportedProtocols() {
        return delegate.getSupportedProtocols();
    }

    /** Not guarded: like 2.5.3 (and the delegate), a failed handshake yields an invalid session, not an exception. */
    @Override
    public SSLSession getSession() {
        return delegate.getSession();
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        delegate.addHandshakeCompletedListener(listener);
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        delegate.removeHandshakeCompletedListener(listener);
    }

    @Override
    public void setUseClientMode(boolean mode) {
        delegate.setUseClientMode(mode);
    }

    @Override
    public boolean getUseClientMode() {
        return delegate.getUseClientMode();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        delegate.setNeedClientAuth(need);
    }

    @Override
    public boolean getNeedClientAuth() {
        return delegate.getNeedClientAuth();
    }

    @Override
    public void setWantClientAuth(boolean want) {
        delegate.setWantClientAuth(want);
    }

    @Override
    public boolean getWantClientAuth() {
        return delegate.getWantClientAuth();
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        delegate.setEnableSessionCreation(flag);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return delegate.getEnableSessionCreation();
    }

    @Override
    public SSLParameters getSSLParameters() {
        return delegate.getSSLParameters();
    }

    @Override
    public void connect(SocketAddress endpoint) throws IOException {
        delegate.connect(endpoint);
    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        delegate.connect(endpoint, timeout);
    }

    @Override
    public void bind(SocketAddress bindpoint) throws IOException {
        delegate.bind(bindpoint);
    }

    @Override
    public InetAddress getInetAddress() {
        return delegate.getInetAddress();
    }

    @Override
    public InetAddress getLocalAddress() {
        return delegate.getLocalAddress();
    }

    @Override
    public int getPort() {
        return delegate.getPort();
    }

    @Override
    public int getLocalPort() {
        return delegate.getLocalPort();
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        return delegate.getRemoteSocketAddress();
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        return delegate.getLocalSocketAddress();
    }

    @Override
    public SocketChannel getChannel() {
        return delegate.getChannel();
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        delegate.setTcpNoDelay(on);
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
        return delegate.getTcpNoDelay();
    }

    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException {
        delegate.setSoLinger(on, linger);
    }

    @Override
    public int getSoLinger() throws SocketException {
        return delegate.getSoLinger();
    }

    @Override
    public void sendUrgentData(int data) throws IOException {
        delegate.sendUrgentData(data);
    }

    @Override
    public void setOOBInline(boolean on) throws SocketException {
        delegate.setOOBInline(on);
    }

    @Override
    public boolean getOOBInline() throws SocketException {
        return delegate.getOOBInline();
    }

    @Override
    public void setSoTimeout(int timeout) throws SocketException {
        delegate.setSoTimeout(timeout);
    }

    @Override
    public int getSoTimeout() throws SocketException {
        return delegate.getSoTimeout();
    }

    @Override
    public void setSendBufferSize(int size) throws SocketException {
        delegate.setSendBufferSize(size);
    }

    @Override
    public int getSendBufferSize() throws SocketException {
        return delegate.getSendBufferSize();
    }

    @Override
    public void setReceiveBufferSize(int size) throws SocketException {
        delegate.setReceiveBufferSize(size);
    }

    @Override
    public int getReceiveBufferSize() throws SocketException {
        return delegate.getReceiveBufferSize();
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException {
        delegate.setKeepAlive(on);
    }

    @Override
    public boolean getKeepAlive() throws SocketException {
        return delegate.getKeepAlive();
    }

    @Override
    public void setTrafficClass(int tc) throws SocketException {
        delegate.setTrafficClass(tc);
    }

    @Override
    public int getTrafficClass() throws SocketException {
        return delegate.getTrafficClass();
    }

    @Override
    public void setReuseAddress(boolean on) throws SocketException {
        delegate.setReuseAddress(on);
    }

    @Override
    public boolean getReuseAddress() throws SocketException {
        return delegate.getReuseAddress();
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }

    @Override
    public void shutdownInput() throws IOException {
        delegate.shutdownInput();
    }

    @Override
    public void shutdownOutput() throws IOException {
        delegate.shutdownOutput();
    }

    @Override
    public boolean isConnected() {
        return delegate.isConnected();
    }

    @Override
    public boolean isBound() {
        return delegate.isBound();
    }

    @Override
    public boolean isClosed() {
        return delegate.isClosed();
    }

    @Override
    public boolean isInputShutdown() {
        return delegate.isInputShutdown();
    }

    @Override
    public boolean isOutputShutdown() {
        return delegate.isOutputShutdown();
    }

    @Override
    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
        delegate.setPerformancePreferences(connectionTime, latency, bandwidth);
    }

    /**
     * The 4.4 libcore hidden {@code public FileDescriptor java.net.Socket.getFileDescriptor$()} (TrafficStats socket
     * tagging, {@code dalvik.system.SocketTagger}, and Conscrypt when this socket is layered under another one): the
     * delegate's descriptor, not this wrapper's own unconnected SocketImpl. Overrides by name and signature (no
     * {@code @Override}: the host JDK lacks the method); called by reflection for the same reason. Null where the
     * delegate class has no such method (host JDK only).
     */
    public FileDescriptor getFileDescriptor$() {
        Method m;
        try {
            m = delegate.getClass().getMethod("getFileDescriptor$");
        } catch (NoSuchMethodException e) {
            return null;
        }
        try {
            // the most-derived declaration may sit in a non-public Conscrypt class
            m.setAccessible(true);
        } catch (SecurityException ignored) {
            // same runtime package on the device (org.conscrypt, one loader): access is allowed without it
        }
        try {
            return (FileDescriptor) m.invoke(delegate);
        } catch (InvocationTargetException e) {
            Throwable c = e.getCause();
            if (c instanceof RuntimeException) {
                throw (RuntimeException) c;
            }
            if (c instanceof Error) {
                throw (Error) c;
            }
            throw new IllegalStateException("getFileDescriptor$ of " + delegate.getClass().getName(), c);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("getFileDescriptor$ of " + delegate.getClass().getName(), e);
        }
    }

    @Override
    public String toString() {
        return "KktlsFilteringSSLSocket[" + delegate + "]";
    }
}
