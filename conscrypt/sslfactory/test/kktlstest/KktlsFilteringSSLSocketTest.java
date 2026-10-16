// SPDX-License-Identifier: Apache-2.0
/*
 * Host test (JUnit 3.8.2, run-host-tests.sh) of org.conscrypt.KktlsFilteringSSLSocket (kktls-sslfilter.jar), the socket the
 * layer-D default factory puts around a Conscrypt 2.6-alpha2 socket to restore Conscrypt 2.5.3's handling of "SSLv3":
 * remove "SSLv3" from the enabled-protocol list, and if that empties the list fail the handshake with 2.5.3's message
 * instead of letting 2.6-alpha2 throw IllegalArgumentException from setEnabledProtocols. The delegate is a recording
 * SSLSocket (RecordingSSLSocket), so each case checks both what the delegate received and that the filter's handshake
 * guard fired before the delegate was reached. The class is loaded through -Dkktlstest.filter (kktls-sslfilter.jar) and
 * used only through the SSLSocket API, never named at compile time: that keeps it absent from the test's own classpath,
 * so the factory test can clear -Dkktlstest.filter to simulate a missing jar.
 */
package kktlstest;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import junit.framework.TestCase;

public class KktlsFilteringSSLSocketTest extends TestCase {
    /** The message Conscrypt 2.5.3 failed the handshake with once "SSLv3" was the only requested protocol. */
    static final String NO_PROTOCOLS = "No enabled protocols; SSLv3 is no longer supported and was filtered from the"
            + " list";
    static final String FILTER_CLASS = "org.conscrypt.KktlsFilteringSSLSocket";

    private RecordingSSLSocket delegate;
    private SSLSocket filter;

    /** The filter class, loaded from -Dkktlstest.filter (kktls-sslfilter.jar), never from the test's own classpath. */
    private static Class<?> loadFilterClass() throws Exception {
        String dir = System.getProperty("kktlstest.filter");
        assertNotNull("run through run-host-tests.sh: -Dkktlstest.filter is not set", dir);
        URLClassLoader cl = new URLClassLoader(new URL[] {new File(dir).toURI().toURL()},
                KktlsFilteringSSLSocketTest.class.getClassLoader());
        return Class.forName(FILTER_CLASS, true, cl);
    }

    private static SSLSocket newFilter(SSLSocket delegate) throws Exception {
        try {
            return (SSLSocket) loadFilterClass().getConstructor(SSLSocket.class).newInstance(delegate);
        } catch (InvocationTargetException e) {
            throw (Exception) e.getCause();
        }
    }

    @Override
    protected void setUp() throws Exception {
        delegate = new RecordingSSLSocket();
        filter = newFilter(delegate);
    }

    public void testIsAnSSLSocket() {
        assertTrue(filter instanceof SSLSocket);
    }

    public void testSslv3OnlyEmptiesTheListAndFailsTheHandshakeAs253() throws Exception {
        filter.setEnabledProtocols(new String[] {"SSLv3"});
        assertEquals("the delegate is given an empty list, not {SSLv3}", "[]",
                Arrays.toString(delegate.enabledProtocols));
        assertEquals("getEnabledProtocols reports the delegate's empty list", 0, filter.getEnabledProtocols().length);
        try {
            filter.startHandshake();
            fail("expected the 2.5.3 handshake failure");
        } catch (SSLHandshakeException e) {
            assertEquals(NO_PROTOCOLS, e.getMessage());
        }
        assertFalse("the delegate's handshake must not be reached", delegate.events.contains("startHandshake"));
    }

    public void testSslv3WithTls12KeepsTls12AndDelegatesTheHandshake() throws Exception {
        filter.setEnabledProtocols(new String[] {"SSLv3", "TLSv1.2"});
        assertEquals("only SSLv3 is removed", "[TLSv1.2]", Arrays.toString(delegate.enabledProtocols));
        filter.startHandshake();
        assertTrue("a non-empty list reaches the delegate's handshake", delegate.events.contains("startHandshake"));
    }

    public void testListWithoutSslv3IsUntouched() throws Exception {
        String[] in = {"TLSv1", "TLSv1.1", "TLSv1.2"};
        filter.setEnabledProtocols(in);
        assertEquals("[TLSv1, TLSv1.1, TLSv1.2]", Arrays.toString(delegate.enabledProtocols));
        filter.startHandshake();
        assertTrue(delegate.events.contains("startHandshake"));
    }

    public void testNullProtocolsAreDelegatedAsNull() throws Exception {
        filter.setEnabledProtocols(null);
        assertNull("null is passed through for the delegate to reject, as before", delegate.enabledProtocols);
        assertTrue(delegate.events.contains("setEnabledProtocols(null)"));
        filter.startHandshake(); // not emptied by an SSLv3 removal
        assertTrue(delegate.events.contains("startHandshake"));
    }

    public void testGetStreamsAreGuardedWhenEmptiedBySslv3() throws Exception {
        filter.setEnabledProtocols(new String[] {"SSLv3"});
        try {
            filter.getInputStream();
            fail("getInputStream must fail like the handshake");
        } catch (SSLHandshakeException e) {
            assertEquals(NO_PROTOCOLS, e.getMessage());
        }
        try {
            filter.getOutputStream();
            fail("getOutputStream must fail like the handshake");
        } catch (SSLHandshakeException e) {
            assertEquals(NO_PROTOCOLS, e.getMessage());
        }
        assertFalse(delegate.events.contains("getInputStream"));
        assertFalse(delegate.events.contains("getOutputStream"));
    }

    public void testReenablingAProtocolClearsTheGuard() throws Exception {
        filter.setEnabledProtocols(new String[] {"SSLv3"});          // emptied
        filter.setEnabledProtocols(new String[] {"TLSv1.2"});        // no longer emptied
        filter.startHandshake();
        assertTrue("the emptied guard is recomputed per call", delegate.events.contains("startHandshake"));
    }

    public void testSetSSLParametersFiltersSslv3() throws Exception {
        SSLParameters params = new SSLParameters();
        params.setProtocols(new String[] {"SSLv3"});
        filter.setSSLParameters(params);
        assertTrue("the delegate's SSLParameters hold no SSLv3", delegate.events.contains("setSSLParameters()"));
        try {
            filter.startHandshake();
            fail("an SSLParameters whose only protocol was SSLv3 empties the list too");
        } catch (SSLHandshakeException e) {
            assertEquals(NO_PROTOCOLS, e.getMessage());
        }
    }

    public void testSetSSLParametersKeepsOtherProtocols() throws Exception {
        SSLParameters params = new SSLParameters();
        params.setProtocols(new String[] {"SSLv3", "TLSv1.2"});
        filter.setSSLParameters(params);
        assertTrue(delegate.events.contains("setSSLParameters(TLSv1.2)"));
        filter.startHandshake();
        assertTrue(delegate.events.contains("startHandshake"));
    }

    public void testSetSSLParametersWithoutProtocolsIsDelegatedUnchanged() throws Exception {
        filter.setSSLParameters(new SSLParameters()); // getProtocols() == null
        assertTrue(delegate.events.contains("setSSLParameters(null)"));
        filter.startHandshake();
        assertTrue(delegate.events.contains("startHandshake"));
    }

    public void testOtherCallsDelegate() throws IOException {
        filter.setUseClientMode(false);
        assertFalse(filter.getUseClientMode());
        filter.setEnabledCipherSuites(new String[] {"TLS_RSA_WITH_AES_128_CBC_SHA"});
        assertEquals("[TLS_RSA_WITH_AES_128_CBC_SHA]", Arrays.toString(filter.getEnabledCipherSuites()));
        filter.close();
        assertTrue(delegate.events.contains("close"));
    }
    // ---- review fixes 2026-10-13: guard only after the delegate accepted, SSLParameters copy, fd, full API ----

    public void testRejectedSetEnabledProtocolsKeepsTheGuardClear() throws Exception {
        filter.setEnabledProtocols(new String[] {"TLSv1.2"});
        delegate.rejectProtocols = true;
        try {
            filter.setEnabledProtocols(new String[] {"SSLv3"});
            fail("the delegate's rejection must reach the caller");
        } catch (IllegalArgumentException expected) {
            // as the delegate threw it
        }
        filter.startHandshake(); // the rejected call did not set the emptied guard
        assertTrue(delegate.events.contains("startHandshake"));
    }

    public void testRejectedSetEnabledProtocolsKeepsTheGuardSet() throws Exception {
        filter.setEnabledProtocols(new String[] {"SSLv3"}); // emptied
        delegate.rejectProtocols = true;
        try {
            filter.setEnabledProtocols(new String[] {"TLSv1.2"});
            fail("the delegate's rejection must reach the caller");
        } catch (IllegalArgumentException expected) {
            // as the delegate threw it
        }
        try {
            filter.startHandshake();
            fail("the rejected call must not clear the emptied guard");
        } catch (SSLHandshakeException e) {
            assertEquals(NO_PROTOCOLS, e.getMessage());
        }
    }

    public void testRejectedSetSSLParametersKeepsTheGuardClear() throws Exception {
        delegate.rejectProtocols = true;
        SSLParameters params = new SSLParameters();
        params.setProtocols(new String[] {"SSLv3"});
        try {
            filter.setSSLParameters(params);
            fail("the delegate's rejection must reach the caller");
        } catch (IllegalArgumentException expected) {
            // as the delegate threw it
        }
        filter.startHandshake();
        assertTrue(delegate.events.contains("startHandshake"));
    }

    public void testSetSSLParametersCopiesWithoutMutatingTheCaller() throws Exception {
        SSLParameters params = new SSLParameters(new String[] {"TLS_RSA_WITH_AES_128_CBC_SHA"},
                new String[] {"SSLv3", "TLSv1.2"});
        params.setNeedClientAuth(true);
        filter.setSSLParameters(params);
        SSLParameters got = delegate.lastParams;
        assertNotNull(got);
        assertNotSame("the delegate gets a copy", params, got);
        assertEquals("[TLS_RSA_WITH_AES_128_CBC_SHA]", Arrays.toString(got.getCipherSuites()));
        assertEquals("[TLSv1.2]", Arrays.toString(got.getProtocols()));
        assertTrue(got.getNeedClientAuth());
        assertFalse(got.getWantClientAuth());
        assertEquals("the caller's object is untouched", "[SSLv3, TLSv1.2]", Arrays.toString(params.getProtocols()));
        assertTrue(params.getNeedClientAuth());
    }

    public void testSetSSLParametersCopiesWantClientAuth() throws Exception {
        SSLParameters params = new SSLParameters(new String[] {"TLS_RSA_WITH_AES_128_CBC_SHA"},
                new String[] {"TLSv1.2"});
        params.setWantClientAuth(true);
        filter.setSSLParameters(params);
        assertTrue(delegate.lastParams.getWantClientAuth());
        assertFalse(delegate.lastParams.getNeedClientAuth());
    }

    public void testGetSessionIsNotGuardedWhenEmptied() throws Exception {
        filter.setEnabledProtocols(new String[] {"SSLv3"});
        // 2.5.3 (and the delegate) answer a failed handshake with an invalid session, never an exception
        assertSame(delegate.getSession(), filter.getSession());
    }

    public void testGetFileDescriptorIsTheDelegates() throws Exception {
        Method m = filter.getClass().getMethod("getFileDescriptor$");
        assertSame("the 4.4 hidden getFileDescriptor$ must return the delegate's descriptor", delegate.fd,
                m.invoke(filter));
        assertTrue(delegate.events.contains("getFileDescriptor$"));
    }

    /** Every public, non-static, non-final method of the 4.4 javax.net.ssl.SSLSocket and java.net.Socket (AOSP 4.4.2
     *  libcore/luni/src/main/java), which the filter must override so none reaches its own unconnected
     *  Socket state. */
    static final String[] API_44 = {
        // SSLSocket
        "getSupportedCipherSuites()", "getEnabledCipherSuites()", "setEnabledCipherSuites([Ljava.lang.String;)",
        "getSupportedProtocols()", "getEnabledProtocols()", "setEnabledProtocols([Ljava.lang.String;)",
        "getSession()", "addHandshakeCompletedListener(javax.net.ssl.HandshakeCompletedListener)",
        "removeHandshakeCompletedListener(javax.net.ssl.HandshakeCompletedListener)", "startHandshake()",
        "setUseClientMode(boolean)", "getUseClientMode()", "setNeedClientAuth(boolean)", "setWantClientAuth(boolean)",
        "getNeedClientAuth()", "getWantClientAuth()", "setEnableSessionCreation(boolean)",
        "getEnableSessionCreation()", "getSSLParameters()", "setSSLParameters(javax.net.ssl.SSLParameters)",
        // Socket
        "close()", "getInetAddress()", "getInputStream()", "getKeepAlive()", "getLocalAddress()", "getLocalPort()",
        "getOutputStream()", "getPort()", "getSoLinger()", "getReceiveBufferSize()", "getSendBufferSize()",
        "getSoTimeout()", "getTcpNoDelay()", "setKeepAlive(boolean)", "setSendBufferSize(int)",
        "setReceiveBufferSize(int)", "setSoLinger(boolean,int)", "setSoTimeout(int)", "setTcpNoDelay(boolean)",
        "toString()", "shutdownInput()", "shutdownOutput()", "getLocalSocketAddress()", "getRemoteSocketAddress()",
        "isBound()", "isConnected()", "isClosed()", "bind(java.net.SocketAddress)", "connect(java.net.SocketAddress)",
        "connect(java.net.SocketAddress,int)", "isInputShutdown()", "isOutputShutdown()", "setReuseAddress(boolean)",
        "getReuseAddress()", "setOOBInline(boolean)", "getOOBInline()", "setTrafficClass(int)", "getTrafficClass()",
        "sendUrgentData(int)", "getChannel()", "getFileDescriptor$()", "setPerformancePreferences(int,int,int)",
    };

    private static String signature(Method m) {
        StringBuilder b = new StringBuilder(m.getName()).append('(');
        Class<?>[] p = m.getParameterTypes();
        for (int i = 0; i < p.length; i++) {
            b.append(i == 0 ? "" : ",").append(p[i].getName());
        }
        return b.append(')').toString();
    }

    public void testFilterOverridesEvery44Method() throws Exception {
        Class<?> c = filter.getClass();
        List<String> declared = new ArrayList<String>();
        for (Method m : c.getDeclaredMethods()) {
            if (Modifier.isPublic(m.getModifiers()) && !Modifier.isStatic(m.getModifiers())) {
                declared.add(signature(m));
            }
        }
        assertEquals("62 methods in the 4.4 list", 62, API_44.length);
        for (String api : API_44) {
            assertTrue(api + " is not overridden by the filter; declared: " + declared, declared.contains(api));
        }
        assertTrue("the filter class is final", Modifier.isFinal(c.getModifiers()));
    }
}
