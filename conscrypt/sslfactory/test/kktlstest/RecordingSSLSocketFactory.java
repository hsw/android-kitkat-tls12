// SPDX-License-Identifier: Apache-2.0
/*
 * Host-test helper (Mac JDK only, never built into the image): an SSLSocketFactory that records every call in a
 * process-wide list and returns fresh marker objects, so a test can see which delegate a wrapper called, with which
 * arguments, and that the wrapper passed the delegate's result through unchanged. Loaded by the test's own class
 * loader, so the stubs in the per-test child loaders (org.conscrypt, com.android.org.conscrypt) share it.
 */
package kktlstest;

import java.net.InetAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.SSLSocketFactory;

public class RecordingSSLSocketFactory extends SSLSocketFactory {
    /** Every call, as "<origin>:<method>(<args>)"; stub events (e.g. "conscrypt:init(...)") go here too. */
    public static final List<String> CALLS = Collections.synchronizedList(new ArrayList<String>());
    /** The object the last call returned. */
    public static Object lastResult;
    /** When set, createSocket returns a RecordingSSLSocket (an SSLSocket) instead of a plain Socket, so a factory test
     *  can observe whether the result is wrapped in the SSLv3 filter. Off by default: the pass-through tests assert the
     *  factory returns the delegate's result unchanged, and a plain Socket is never wrapped. */
    public static boolean returnSslSocket;

    public final String origin;

    public RecordingSSLSocketFactory(String origin) {
        this.origin = origin;
    }

    public static synchronized void reset() {
        CALLS.clear();
        lastResult = null;
        returnSslSocket = false;
    }

    private static Socket newSocket() {
        return returnSslSocket ? new RecordingSSLSocket() : new Socket();
    }

    private synchronized <T> T record(String call, T result) {
        CALLS.add(origin + ":" + call);
        lastResult = result;
        return result;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return record("getDefaultCipherSuites()", new String[] {origin + "-default"});
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return record("getSupportedCipherSuites()", new String[] {origin + "-supported"});
    }

    @Override
    public Socket createSocket() {
        return record("createSocket()", newSocket());
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) {
        return record("createSocket(Socket," + host + "," + port + "," + autoClose + ")", newSocket());
    }

    @Override
    public Socket createSocket(String host, int port) {
        return record("createSocket(" + host + "," + port + ")", newSocket());
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) {
        return record("createSocket(" + host + "," + port + "," + localHost.getHostAddress() + "," + localPort + ")",
                newSocket());
    }

    @Override
    public Socket createSocket(InetAddress host, int port) {
        return record("createSocket(" + host.getHostAddress() + "," + port + ")", newSocket());
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) {
        return record("createSocket(" + address.getHostAddress() + "," + port + "," + localAddress.getHostAddress()
                + "," + localPort + ")", newSocket());
    }
}
