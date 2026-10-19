// SPDX-License-Identifier: Apache-2.0
/*
 * Tls12Probe: runtime probe of the Java TLS defaults on an Android 4.4 image (layer A, Task 8; layer D, Task 11).
 * Runs under app_process (`CLASSPATH=/data/local/tmp/tls12probe.jar app_process /system/bin Tls12Probe <command> ...`,
 * as tools/tls-probe.sh does, so the framework natives are registered as for `am`) on the emulator or a device; the boot
 * class path is the system's, so every factory below is the one apps get. Built by tools/tls-probe.sh build
 * (javac --release 8 + d8 --min-api 19); the source keeps to Java 6 syntax.
 *
 * Commands (one result line per target, "RESULT <name> OK|FAIL ..." so a script can grep it). A FAIL line always starts
 * with "FAIL class=<c>": handshake (TLS alert, protocol or cipher refusal), cert (certificate path/trust/validity),
 * hostname (name check), network (DNS, connect, reset, EOF, timeout: no TLS evidence at all) or other; see classify().
 *   dump                      enabled/supported protocols and suites of the default client and server factories,
 *                             SSLContext.getDefault(), SSLContext "TLS", and android.net.SSLCertificateSocketFactory
 *   url <name> <url>          HttpsURLConnection (okhttp) GET; prints code, cipher suite, first bytes of the body
 *   socket <name> <host> <port>  SSLSocketFactory.getDefault() handshake; prints protocol and suite, then checks the
 *                             host name with HttpsURLConnection.getDefaultHostnameVerifier()
 *   certsock <name> <host> <port>  same through SSLCertificateSocketFactory.getDefault(10000)
 *   apache <name> <url>       org.apache.http DefaultHttpClient GET (the client most 4.4 apps used)
 * Layer D (Task 11; the default factory is the kktls-sslfactory wrapper over Conscrypt 2.5.3):
 *   csock <name> <host> <port> default|platform <protocols|->
 *                             one handshake through getDefault() (gate on: the wrapper's Conscrypt) or
 *                             SSLCertificateSocketFactory, optionally restricted to the comma-separated protocols
 *   both <name> <phost> <pport> <chost> <cport> <cprotocols|-> conscrypt-first|platform-first
 *                             one process, both TLS stacks: SSLCertificateSocketFactory (platform, libjavacrypto +
 *                             libssl) to phost and SSLSocketFactory.getDefault() (Conscrypt/BoringSSL in
 *                             libkktls_conscrypt_jni.so) to chost, in the given order; then which libraries are mapped.
 *                             RESULT OK only with positive evidence of both stacks (bothVerdict): the default factory
 *                             is the wrapper over Conscrypt ("[conscrypt: "), the default step's socket is an
 *                             org.conscrypt class from the wrapper's loader of kktls-conscrypt.jar, the platform step's a
 *                             platform class of the boot class path (socketOrigin: com.android.org.conscrypt on 4.4,
 *                             org.apache.harmony.xnet.provider.jsse.OpenSSL* on 4.1-4.3), and the libraries are mapped
 *                             (Conscrypt's, and on 4.4 the platform's libjavacrypto.so; on 4.1-4.3 NativeCrypto lives in
 *                             libjavacore.so, which links libssl/libcrypto and every Dalvik process maps from the zygote,
 *                             so there the maps say nothing about the platform stack and its evidence is the platform
 *                             step's class and handshake alone; review 3, codex 5: a wrapper that fell back after
 *                             loading its library gave two platform handshakes and OK)
 *   fallback <name> <host> <port>  pid, the default factory's toString(), three more wrapper instances (the log-once
 *                             check is done by the caller in logcat), one handshake through getDefault() (port 0: none)
 *   shadow <name> <host> <port>  an app that bundles org.conscrypt: this jar carries a stub
 *                             org.conscrypt.Conscrypt (field KKTLS_APP_COPY); which copy the app's class loader returns
 *                             (kktls-conscrypt.jar is not on the boot class path, so it must be the app's own in both gate
 *                             states), whether the boot class loader sees any org.conscrypt.Conscrypt, and what the
 *                             default factory maps (port 0: no handshake). No Conscrypt library is loaded from the
 *                             probe's loader: its JNI_OnLoad needs a real org.conscrypt.NativeCrypto, and the stub has none
 *   appmix <name> <host> <port> <appjar> <applibdir> <protocols|-> app-first|default-first
 *                             review 1b: an app that bundles a real Conscrypt (its dex jar and its libconscrypt_jni.so,
 *                             loaded through its own dalvik.system.PathClassLoader(appjar, applibdir, boot) as an app's
 *                             loader is) next to the default factory (gate on: the wrapper's Conscrypt with
 *                             libkktls_conscrypt_jni.so) in one process: four handshakes, first, second, first, second
 *                             (the second library's JNI_OnLoad must not break the first user), each from the expected
 *                             class loader; then which Conscrypt libraries are mapped (two distinct files = the linker
 *                             kept both). A process abort prints no RESULT line
 *   sniprop <name> <value> <host> <port> <protocols|->
 *                             review 1b: System.setProperty("jsse.enableSNIExtension", value) before the first
 *                             getDefault(), then the default factory, whether libkktls_conscrypt_jni.so got mapped, and one
 *                             handshake through it (a value Conscrypt rejects must give the platform-sni delegate)
 *   mem <name> url:<url>|load|local:<host>:<port>:<protocols>
 *                             PSS of this process (/proc/self/smaps) before and after one TLS use, with the PSS of the
 *                             TLS-related mappings
 * Layer-D gate (Task 11b; persist.kktls.conscrypt, exactly "1" = Conscrypt, anything else = layer A):
 *   gate <name> <host> <port> [<flip>]
 *                             the gate value as this process reads it, the default factory's toString(), its enabled
 *                             protocols, whether libkktls_conscrypt_jni.so and any kktls-conscrypt dex (the jar, its
 *                             dalvik-cache file) are mapped, one handshake through getDefault()
 *                             (port 0: none); with <flip> (root), the property is set to <flip> after the default
 *                             factory exists, a new wrapper is made (it must keep this process's first reading), and
 *                             the old value is set back
 * App-set protocols and suites (post-EOL plan Task 9; series README "Compatibility"):
 *   setters <name> <host> <port> default|context
 *                             six cases, each on a new socket of SSLSocketFactory.getDefault() (default) or of
 *                             SSLContext.getDefault().getSocketFactory() (context, always the platform):
 *                             setEnabledCipherSuites with {RC4} (rc4), {RC4, ECDHE-RSA-AES128-GCM} (rc4-mixed),
 *                             {TLS_AES_128_GCM_SHA256, ECDHE-RSA-AES128-GCM} (tls13-mixed), and setEnabledProtocols with
 *                             {SSLv3} (sslv3), {SSLv3, TLSv1.2} (mixed-protocols) and {SSLv3, TLSv1, TLSv1.1, TLSv1.2}
 *                             (sslv3-plus), the protocol cases followed by a handshake to host:port (port 0: none). One "SETTER <name> <case> ok|BAD <outcome>" line each; the
 *                             expected outcome depends on the socket's stack (socketOrigin, settersCaseOk): Conscrypt
 *                             2.5.3 (gate on, default) throws IllegalArgumentException for any RC4 name (no filtering),
 *                             drops TLS 1.3 suite names, silently drops "SSLv3" (alone: no protocol left, the
 *                             handshake fails "No enabled protocols") and keeps the TLS versions of the mixed lists
 *                             (TLSv1.2 handshakes); the platform (layer A; 4.4 and the 4.1-4.3 harmony stack alike)
 *                             accepts RC4 and SSLv3 as opt-ins (libcore/0026) and refuses the TLS 1.3 name; to a server
 *                             without SSLv3 its {SSLv3} and also its {SSLv3, TLSv1.2} handshake fail (OpenSSL 1.0.1
 *                             s23_clnt.c keeps the enabled versions contiguous: TLSv1 off with SSLv3 on caps the hello
 *                             at SSLv3), {SSLv3, TLSv1, TLSv1.1, TLSv1.2} gives TLSv1.2.
 *                             RESULT OK stack=<stack> only when every case is as expected for that stack
 * Self-check (no network, runs on the host JVM too, see tools/tls-probe.sh selftest):
 *   selftest                  classify() on synthetic cause chains, socketOrigin(), bothVerdict() and settersCaseOk()
 *                             on synthetic inputs; "selftest ok|FAIL" per case, SELFTEST PASS|FAIL, exit 1 on a failure
 */
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class Tls12Probe {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            return;
        }
        String cmd = args[0];
        if (cmd.equals("dump")) {
            dump();
        } else if (cmd.equals("url") && args.length == 3) {
            url(args[1], args[2]);
        } else if (cmd.equals("socket") && args.length == 4) {
            socket(args[1], args[2], Integer.parseInt(args[3]), false);
        } else if (cmd.equals("certsock") && args.length == 4) {
            socket(args[1], args[2], Integer.parseInt(args[3]), true);
        } else if (cmd.equals("apache") && args.length == 3) {
            apache(args[1], args[2]);
        } else if (cmd.equals("both") && args.length == 8) {
            both(args[1], args[2], Integer.parseInt(args[3]), args[4], Integer.parseInt(args[5]), args[6],
                    args[7].equals("platform-first"));
        } else if (cmd.equals("csock") && args.length == 6) {
            csock(args[1], args[2], Integer.parseInt(args[3]), args[4], args[5]);
        } else if (cmd.equals("fallback") && args.length == 4) {
            fallback(args[1], args[2], Integer.parseInt(args[3]));
        } else if (cmd.equals("shadow") && args.length == 4) {
            shadow(args[1], args[2], Integer.parseInt(args[3]));
        } else if (cmd.equals("appmix") && args.length == 8) {
            appmix(args[1], args[2], Integer.parseInt(args[3]), args[4], args[5], args[6], args[7].equals("app-first"));
        } else if (cmd.equals("sniprop") && args.length == 6) {
            sniprop(args[1], args[2], args[3], Integer.parseInt(args[4]), args[5]);
        } else if (cmd.equals("mem") && args.length == 3) {
            mem(args[1], args[2]);
        } else if (cmd.equals("gate") && (args.length == 4 || args.length == 5)) {
            gate(args[1], args[2], Integer.parseInt(args[3]), args.length == 5 ? args[4] : null);
        } else if (cmd.equals("setters") && args.length == 5) {
            setters(args[1], args[2], Integer.parseInt(args[3]), args[4]);  // default|context
        } else if (cmd.equals("selftest") && args.length == 1) {
            System.exit(selftest());
        } else {
            usage();
            System.exit(2);
        }
    }

    private static void usage() {
        System.out.println("usage: Tls12Probe dump | url NAME URL | socket NAME HOST PORT | certsock NAME HOST PORT"
                + " | apache NAME URL | csock NAME HOST PORT default|platform PROTOS|-"
                + " | both NAME PHOST PPORT CHOST CPORT CPROTOS|- conscrypt-first|platform-first"
                + " | fallback NAME HOST PORT | shadow NAME HOST PORT | mem NAME url:URL|load|local:HOST:PORT:PROTOS"
                + " | appmix NAME HOST PORT APPJAR APPLIBDIR PROTOS|- app-first|default-first"
                + " | sniprop NAME VALUE HOST PORT PROTOS|-"
                + " | gate NAME HOST PORT [FLIP] | setters NAME HOST PORT default|context | selftest");
    }

    // ---- dump ---------------------------------------------------------------------------------------------------

    private static void dump() throws Exception {
        System.out.println("java.vm.version=" + System.getProperty("java.vm.version")
                + " os.arch=" + System.getProperty("os.arch"));
        System.out.println("jsse.enableSNIExtension=" + System.getProperty("jsse.enableSNIExtension"));
        java.security.Provider[] ps = java.security.Security.getProviders();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < ps.length; i++) {
            sb.append(i + 1).append('=').append(ps[i].getName()).append(' ');
        }
        System.out.println("providers " + sb.toString().trim());
        System.out.println("ssl.SocketFactory.provider=" + java.security.Security.getProperty("ssl.SocketFactory.provider"));

        dumpClient("SSLSocketFactory.getDefault()", (SSLSocketFactory) SSLSocketFactory.getDefault());
        dumpClient("SSLContext.getDefault()", SSLContext.getDefault().getSocketFactory());
        SSLContext tls = SSLContext.getInstance("TLS");
        tls.init(null, null, null);
        dumpClient("SSLContext.getInstance(TLS)", tls.getSocketFactory());
        dumpClient("HttpsURLConnection.getDefaultSSLSocketFactory()", HttpsURLConnection.getDefaultSSLSocketFactory());
        try {
            dumpClient("SSLCertificateSocketFactory.getDefault(0)",
                    (SSLSocketFactory) android.net.SSLCertificateSocketFactory.getDefault(0));
        } catch (Throwable t) {
            System.out.println("RESULT dump-certsockfactory FAIL " + describe(t));
        }
        SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        System.out.println("== SSLServerSocketFactory.getDefault() " + ssf.getClass().getName());
        System.out.println("server default suites " + list(ssf.getDefaultCipherSuites()));
        SSLServerSocket ss = (SSLServerSocket) ssf.createServerSocket(0);
        try {
            System.out.println("server socket " + ss.getClass().getName());
            System.out.println("server enabled protocols " + list(ss.getEnabledProtocols()));
            System.out.println("server enabled suites " + list(ss.getEnabledCipherSuites()));
        } finally {
            ss.close();
        }
        System.out.println("RESULT dump OK");
    }

    private static void dumpClient(String name, SSLSocketFactory f) throws Exception {
        System.out.println("== " + name + " " + f.getClass().getName());
        System.out.println("factory " + f);
        System.out.println("factory default suites " + list(f.getDefaultCipherSuites()));
        System.out.println("factory supported suites (" + f.getSupportedCipherSuites().length + ") "
                + list(f.getSupportedCipherSuites()));
        SSLSocket s = (SSLSocket) f.createSocket();
        try {
            System.out.println("socket " + s.getClass().getName());
            System.out.println("enabled protocols " + list(s.getEnabledProtocols()));
            System.out.println("supported protocols " + list(s.getSupportedProtocols()));
            System.out.println("enabled suites (" + s.getEnabledCipherSuites().length + ") "
                    + list(s.getEnabledCipherSuites()));
        } finally {
            s.close();
        }
    }

    private static String list(String[] a) {
        return Arrays.asList(a).toString();
    }

    // ---- network ------------------------------------------------------------------------------------------------

    private static void url(String name, String u) {
        long t0 = System.currentTimeMillis();
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(u).openConnection();
            c.setConnectTimeout(20000);
            c.setReadTimeout(20000);
            int code = c.getResponseCode();
            String suite = (c instanceof HttpsURLConnection) ? ((HttpsURLConnection) c).getCipherSuite() : "-";
            String body = readSome(code < 400 ? c.getInputStream() : c.getErrorStream(), 16384);
            System.out.println("BODY " + name + " " + body.replace('\n', ' '));
            System.out.println("RESULT " + name + " OK code=" + code + " suite=" + suite + " impl="
                    + c.getClass().getName() + " ms=" + (System.currentTimeMillis() - t0));
        } catch (Throwable t) {
            System.out.println("RESULT " + name + " FAIL " + fail(t) + " ms=" + (System.currentTimeMillis() - t0));
        } finally {
            if (c != null) {
                c.disconnect();
            }
        }
    }

    private static void socket(String name, String host, int port, boolean certFactory) {
        long t0 = System.currentTimeMillis();
        SSLSocket s = null;
        try {
            SSLSocketFactory f = certFactory
                    ? (SSLSocketFactory) android.net.SSLCertificateSocketFactory.getDefault(10000)
                    : (SSLSocketFactory) SSLSocketFactory.getDefault();
            s = (SSLSocket) f.createSocket(host, port);
            s.setSoTimeout(20000);
            s.startHandshake();
            SSLSession ss = s.getSession();
            HostnameVerifier hv = HttpsURLConnection.getDefaultHostnameVerifier();
            boolean hostOk = hv.verify(host, ss);
            System.out.println("RESULT " + name + (hostOk ? " OK" : " FAIL class=hostname hostname-mismatch") + " protocol="
                    + ss.getProtocol() + " suite=" + ss.getCipherSuite() + " ms=" + (System.currentTimeMillis() - t0));
        } catch (Throwable t) {
            System.out.println("RESULT " + name + " FAIL " + fail(t) + " ms=" + (System.currentTimeMillis() - t0));
        } finally {
            if (s != null) {
                try {
                    s.close();
                } catch (Exception ignored) {
                    // closing a failed socket
                }
            }
        }
    }

    /** One handshake; returns "protocol=... suite=..." or throws. */
    private static String handshake(SSLSocketFactory f, String host, int port) throws Exception {
        SSLSocket s = (SSLSocket) f.createSocket(host, port);
        try {
            s.setSoTimeout(20000);
            s.startHandshake();
            SSLSession ss = s.getSession();
            if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, ss)) {
                throw new javax.net.ssl.SSLPeerUnverifiedException("hostname mismatch for " + host);
            }
            return "protocol=" + ss.getProtocol() + " suite=" + ss.getCipherSuite() + " socket="
                    + s.getClass().getName();
        } finally {
            s.close();
        }
    }

    // ---- layer D ------------------------------------------------------------------------------------------------

    /**
     * SSLSocketFactory.getDefault() (gate on: the wrapper's Conscrypt), SSLCertificateSocketFactory (platform) or
     * SSLContext.getDefault()'s factory ("context", platform; setters uses it because SSLCertificateSocketFactory's
     * createSocket(host, port) already shakes hands to check the host name, before a setter could act). There
     * is no "Conscrypt.newProvider() by reflection" source any more: org.conscrypt is not on the boot class path, so
     * reflection from this jar finds only its own shadow stub (the isolation the shadow check proves).
     */
    private static SSLSocketFactory factory(String source) throws Exception {
        if (source.equals("default")) {
            return (SSLSocketFactory) SSLSocketFactory.getDefault();
        }
        if (source.equals("platform")) {
            return (SSLSocketFactory) android.net.SSLCertificateSocketFactory.getDefault(10000);
        }
        if (source.equals("context")) {
            return SSLContext.getDefault().getSocketFactory();
        }
        throw new IllegalArgumentException("source " + source + ", want default, platform or context");
    }

    /** One handshake through factory(source), optionally restricted to the comma-separated protocols ("-" = default). */
    private static String handshake(String source, String host, int port, String protos) throws Exception {
        return handshakeFrom(source, host, port, protos)[0];
    }

    /** handshake(source, ...) and where its socket's classes come from: {"protocol=... socket=...", socketOrigin()}. */
    private static String[] handshakeFrom(String source, String host, int port, String protos) throws Exception {
        SSLSocketFactory f = factory(source);
        SSLSocket s = (SSLSocket) f.createSocket(host, port);
        try {
            if (!protos.equals("-")) {
                s.setEnabledProtocols(protos.split(","));
            }
            s.setSoTimeout(20000);
            s.startHandshake();
            SSLSession ss = s.getSession();
            if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, ss)) {
                throw new javax.net.ssl.SSLPeerUnverifiedException("hostname mismatch for " + host);
            }
            Class<?> c = s.getClass();
            return new String[] {"protocol=" + ss.getProtocol() + " suite=" + ss.getCipherSuite() + " socket="
                    + c.getName(), socketOrigin(c.getName(), String.valueOf(c.getClassLoader()),
                    c.getClassLoader() == SSLSocketFactory.class.getClassLoader())};
        } finally {
            s.close();
        }
    }

    /**
     * Where a socket's classes come from: "conscrypt" (an org.conscrypt class from the wrapper's own loader of
     * kktls-conscrypt.jar, which is not on the boot class path), "platform" (from the boot class path: a
     * com.android.org.conscrypt class, the 4.4 OpenSSL stack, or an org.apache.harmony.xnet.provider.jsse.OpenSSL* class,
     * the 4.1-4.3 one; not harmony's pure-Java SSLSocketImpl) or "other".
     */
    static String socketOrigin(String className, String loader, boolean bootLoader) {
        if (className.startsWith("org.conscrypt.") && !bootLoader && loader.indexOf("kktls-conscrypt.jar") >= 0) {
            return "conscrypt";
        }
        if (className.startsWith("com.android.org.conscrypt.") && bootLoader) {
            return "platform";
        }
        if (className.startsWith("org.apache.harmony.xnet.provider.jsse.OpenSSL") && bootLoader) {
            return "platform";
        }
        return "other";
    }

    /**
     * The verdict of both: every step OK, the default factory is the wrapper over Conscrypt, the default step's socket
     * from Conscrypt and the platform step's from the platform (socketOrigin), and both stacks' libraries mapped.
     */
    static boolean bothVerdict(boolean stepsOk, String defaultFactory, String conscryptFrom, String platformFrom,
            String maps, boolean jb) {
        return stepsOk && defaultFactory.indexOf("[conscrypt: ") >= 0 && conscryptFrom.equals("conscrypt")
                && platformFrom.equals("platform") && bothMapped(maps, jb);
    }

    /**
     * Both stacks' libraries in maps: the Conscrypt library, and on 4.4 the platform's libjavacrypto.so. On 4.1-4.3
     * (jb) NativeCrypto lives in libjavacore.so, which links libssl.so and libcrypto.so and which every Dalvik process
     * maps from the zygote, so no mapping there proves the platform stack ran; the platform evidence on Jelly Bean is
     * the platform step's socket class (socketOrigin "platform") and its handshake, checked in bothVerdict.
     */
    static boolean bothMapped(String maps, boolean jb) {
        return maps.indexOf("/" + SYSTEM_JNI) >= 0 && (jb || maps.indexOf("libjavacrypto.so") >= 0);
    }

    private static void csock(String name, String host, int port, String source, String protos) {
        long t0 = System.currentTimeMillis();
        try {
            System.out.println("RESULT " + name + " OK " + handshake(source, host, port, protos) + " ms="
                    + (System.currentTimeMillis() - t0));
        } catch (Throwable t) {
            System.out.println("RESULT " + name + " FAIL " + fail(t) + " ms=" + (System.currentTimeMillis() - t0));
        }
    }

    // ---- layer D ------------------------------------------------------------------------------------------------

    /**
     * Both TLS stacks in one process: a handshake through SSLCertificateSocketFactory (platform: libjavacrypto +
     * libssl 1.0.1u; on 4.1-4.3 libjavacore + libssl) and one through SSLSocketFactory.getDefault() (Conscrypt:
     * libkktls_conscrypt_jni.so, BoringSSL), in the given order; the Conscrypt step may be restricted to some protocols
     * ("-" = its defaults).
     */
    private static void both(String name, String phost, int pport, String chost, int cport, String cprotos,
            boolean platformFirst) {
        boolean ok = true;
        String conscryptFrom = "none";
        String platformFrom = "none";
        for (int i = 0; i < 2; i++) {
            boolean platform = (i == 0) == platformFirst;
            long t0 = System.currentTimeMillis();
            try {
                String[] r = platform ? handshakeFrom("platform", phost, pport, "-")
                        : handshakeFrom("default", chost, cport, cprotos);
                if (platform) {
                    platformFrom = r[1];
                } else {
                    conscryptFrom = r[1];
                }
                System.out.println("STEP " + name + " " + (i + 1) + " " + (platform ? "platform" : "conscrypt") + " OK "
                        + r[0] + " from=" + r[1] + " ms=" + (System.currentTimeMillis() - t0));
            } catch (Throwable t) {
                ok = false;
                System.out.println("STEP " + name + " " + (i + 1) + " " + (platform ? "platform" : "conscrypt")
                        + " FAIL " + fail(t));
            }
        }
        String def;
        try {
            def = String.valueOf(SSLSocketFactory.getDefault());
        } catch (Throwable t) {
            def = "n/a " + describe(t);
        }
        String m = mapped(SYSTEM_JNI, "libjavacrypto.so", "libssl.so", "libcrypto.so");
        // the String field: d8 --min-api 19 folds "Build.VERSION.SDK_INT < 19" to false (found on 4.3)
        boolean jb = Integer.parseInt(android.os.Build.VERSION.SDK) < 19;
        boolean both = bothMapped(m, jb);
        boolean conscrypt = def.indexOf("[conscrypt: ") >= 0;
        System.out.println("DEFAULT " + name + " " + def);
        System.out.println("MAPS " + name + " " + m);
        System.out.println("RESULT " + name + (bothVerdict(ok, def, conscryptFrom, platformFrom, m, jb) ? " OK"
                : " FAIL class=other") + " order=" + (platformFirst ? "platform" : "conscrypt")
                + "-first both-stacks-mapped=" + both + " default-is-conscrypt=" + conscrypt + " conscrypt-step-from="
                + conscryptFrom + " platform-step-from=" + platformFrom);
    }

    /** Fallback check: pid, the default factory, three more wrappers, enabled defaults; port 0 = no handshake. */
    private static void fallback(String name, String host, int port) {
        System.out.println("PID " + name + " " + android.os.Process.myPid());
        try {
            SSLSocketFactory d = (SSLSocketFactory) SSLSocketFactory.getDefault();
            System.out.println("DEFAULT " + name + " " + d.getClass().getName() + " " + d);
            Class<?> w = Class.forName("io.github.hsw.kktls.KktlsDefaultSSLSocketFactory");
            for (int i = 0; i < 3; i++) {
                System.out.println("INSTANCE " + name + " " + (i + 2) + " " + w.newInstance());
            }
            SSLSocket s = (SSLSocket) d.createSocket();
            System.out.println("ENABLED " + name + " protocols=" + list(s.getEnabledProtocols()) + " suites("
                    + s.getEnabledCipherSuites().length + ")=" + list(s.getEnabledCipherSuites()));
            s.close();
            System.out.println("DEX " + name + " " + mappedContaining("kktls-conscrypt"));
            System.out.println("RESULT " + name + " OK " + (port == 0 ? "no handshake" : handshake(d, host, port)));
        } catch (Throwable t) {
            System.out.println("RESULT " + name + " FAIL " + fail(t));
        }
    }

    static final String GATE = "persist.kktls.conscrypt";
    static final String WRAPPER = "io.github.hsw.kktls.KktlsDefaultSSLSocketFactory";
    /** The wrapper's Conscrypt library (review 1b: renamed by the build) and the name an app's bundled Conscrypt loads. */
    static final String SYSTEM_JNI = "libkktls_conscrypt_jni.so";
    static final String APP_JNI = "libconscrypt_jni.so";

    /**
     * An app that bundles Conscrypt next to the default factory (see the header, command appmix). The app's loader is
     * built like an app's: PathClassLoader(appjar, applibdir, the boot class loader), so this jar's shadow stub is not
     * in its way; its Conscrypt loads libconscrypt_jni.so from applibdir. RESULT OK only when all four handshakes work,
     * the app steps use the app's classes and the default steps the wrapper's (kktls-conscrypt.jar), the default factory
     * is the wrapper over Conscrypt, and both libraries are mapped as two files.
     */
    private static void appmix(String name, String host, int port, String appJar, String appLibDir, String protos,
            boolean appFirst) {
        System.out.println("PID " + name + " " + android.os.Process.myPid());
        boolean ok = true;
        SSLSocketFactory app = null;
        SSLSocketFactory def = null;
        for (int i = 0; i < 4; i++) {
            boolean isApp = (i % 2 == 0) == appFirst;
            String who = isApp ? "app" : "default";
            long t0 = System.currentTimeMillis();
            try {
                if (isApp && app == null) {
                    ClassLoader boot = SSLSocketFactory.class.getClassLoader();
                    ClassLoader cl = (ClassLoader) Class.forName("dalvik.system.PathClassLoader")
                            .getConstructor(String.class, String.class, ClassLoader.class)
                            .newInstance(appJar, appLibDir, boot);
                    java.security.Provider p = (java.security.Provider) Class.forName("org.conscrypt.Conscrypt", true,
                            cl).getMethod("newProvider").invoke(null);
                    SSLContext ctx = SSLContext.getInstance("TLS", p);
                    ctx.init(null, null, null);
                    app = ctx.getSocketFactory();
                    System.out.println("APP " + name + " provider " + p.getName() + " " + p.getInfo() + " loader=" + cl);
                } else if (!isApp && def == null) {
                    def = (SSLSocketFactory) SSLSocketFactory.getDefault();
                    System.out.println("DEFAULT " + name + " " + def);
                }
                SSLSocket s = (SSLSocket) (isApp ? app : def).createSocket(host, port);
                String r;
                try {
                    if (!protos.equals("-")) {
                        s.setEnabledProtocols(protos.split(","));
                    }
                    s.setSoTimeout(20000);
                    s.startHandshake();
                    SSLSession ss = s.getSession();
                    String loader = String.valueOf(s.getClass().getClassLoader());
                    String from = loader.indexOf(appJar) >= 0 ? "app" : loader.indexOf("kktls-conscrypt.jar") >= 0
                            ? "default" : "other";
                    r = "protocol=" + ss.getProtocol() + " suite=" + ss.getCipherSuite() + " socket="
                            + s.getClass().getName() + " classes-from=" + from;
                    if (!from.equals(who)) {
                        throw new IllegalStateException("socket classes from " + from + " (" + loader + "), want "
                                + who);
                    }
                } finally {
                    s.close();
                }
                System.out.println("STEP " + name + " " + (i + 1) + " " + who + " OK " + r + " ms="
                        + (System.currentTimeMillis() - t0));
            } catch (Throwable t) {
                ok = false;
                System.out.println("STEP " + name + " " + (i + 1) + " " + who + " FAIL " + fail(t));
            }
        }
        String m = mapped(SYSTEM_JNI, APP_JNI);
        boolean two = m.indexOf("/" + SYSTEM_JNI) >= 0 && m.indexOf(appLibDir + "/" + APP_JNI) >= 0;
        boolean conscrypt = def != null && def.toString().indexOf("[conscrypt: ") >= 0;
        System.out.println("MAPS " + name + " " + m);
        System.out.println("RESULT " + name + (ok && two && conscrypt ? " OK" : " FAIL class=other") + " order="
                + (appFirst ? "app" : "default") + "-first two-libraries-mapped=" + two + " default-is-conscrypt="
                + conscrypt);
    }

    /** jsse.enableSNIExtension set before the first getDefault() (see the header, command sniprop). */
    private static void sniprop(String name, String value, String host, int port, String protos) {
        System.out.println("PID " + name + " " + android.os.Process.myPid());
        try {
            System.setProperty("jsse.enableSNIExtension", value);
            SSLSocketFactory d = (SSLSocketFactory) SSLSocketFactory.getDefault();
            System.out.println("DEFAULT " + name + " " + d);
            System.out.println("MAPS " + name + " " + mapped(SYSTEM_JNI));
            SSLSocket s = (SSLSocket) d.createSocket(host, port);
            try {
                if (!protos.equals("-")) {
                    s.setEnabledProtocols(protos.split(","));
                }
                s.setSoTimeout(20000);
                s.startHandshake();
                System.out.println("RESULT " + name + " OK protocol=" + s.getSession().getProtocol() + " suite="
                        + s.getSession().getCipherSuite() + " value=\"" + value + "\"");
            } finally {
                s.close();
            }
        } catch (Throwable t) {
            System.out.println("RESULT " + name + " FAIL " + fail(t) + " value=\"" + value + "\"");
        }
    }

    /** SystemProperties.get/set by reflection (hidden API; app_process registers the natives). */
    private static String sysprop(String key) throws Exception {
        return (String) Class.forName("android.os.SystemProperties").getMethod("get", String.class, String.class)
                .invoke(null, key, "");
    }

    private static void setprop(String key, String value) throws Exception {
        Class.forName("android.os.SystemProperties").getMethod("set", String.class, String.class)
                .invoke(null, key, value);
    }

    /** The layer-D gate: see the header (command gate). */
    private static void gate(String name, String host, int port, String flip) {
        System.out.println("PID " + name + " " + android.os.Process.myPid());
        try {
            String before = sysprop(GATE);
            System.out.println("GATE " + name + " value=\"" + before + "\"");
            SSLSocketFactory d = (SSLSocketFactory) SSLSocketFactory.getDefault();
            System.out.println("DEFAULT " + name + " " + d.getClass().getName() + " " + d);
            SSLSocket s = (SSLSocket) d.createSocket();
            System.out.println("ENABLED " + name + " protocols=" + list(s.getEnabledProtocols()) + " suites("
                    + s.getEnabledCipherSuites().length + ")");
            s.close();
            if (flip != null) {
                setprop(GATE, flip);
                Object w = Class.forName(WRAPPER).newInstance();
                System.out.println("AFTER-SETPROP " + name + " value=\"" + sysprop(GATE) + "\" new-instance " + w);
                setprop(GATE, before);
                System.out.println("RESTORED " + name + " value=\"" + sysprop(GATE) + "\"");
            }
            System.out.println("MAPS " + name + " " + mapped(SYSTEM_JNI, APP_JNI));
            System.out.println("DEX " + name + " " + mappedContaining("kktls-conscrypt"));
            System.out.println("RESULT " + name + " OK " + (port == 0 ? "no handshake" : handshake(d, host, port)));
        } catch (Throwable t) {
            System.out.println("RESULT " + name + " FAIL " + fail(t));
        }
    }

    // ---- setters (post-EOL plan Task 9) -----------------------------------------------------------------------

    static final String RC4 = "SSL_RSA_WITH_RC4_128_SHA";
    static final String GCM = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
    static final String TLS13_SUITE = "TLS_AES_128_GCM_SHA256";
    static final String[] SETTER_CASES = {"rc4", "rc4-mixed", "tls13-mixed", "sslv3", "mixed-protocols", "sslv3-plus"};

    /**
     * App-set suites and protocols on sockets of factory(source) (see the header, command setters). The stack is
     * taken from the first socket's class (socketOrigin); every case must give the outcome settersCaseOk() expects for
     * it. A case's outcome is "throws <class>: <message>" when the setter threw, else "accepted enabled=[...]" (what the
     * socket's getter returns afterwards), for the protocol cases followed by " handshake=OK protocol=... suite=...",
     * " handshake=FAIL class=..." or " handshake=none" (port 0).
     */
    private static void setters(String name, String host, int port, String source) {
        try {
            SSLSocketFactory f = factory(source);
            System.out.println("DEFAULT " + name + " " + f.getClass().getName() + " " + f);
            SSLSocket probe = (SSLSocket) f.createSocket();
            Class<?> c = probe.getClass();
            String stack = socketOrigin(c.getName(), String.valueOf(c.getClassLoader()),
                    c.getClassLoader() == SSLSocketFactory.class.getClassLoader());
            System.out.println("SOCKET " + name + " " + c.getName() + " from=" + stack + " protocols="
                    + list(probe.getEnabledProtocols()) + " suites(" + probe.getEnabledCipherSuites().length + ")");
            probe.close();
            int bad = 0;
            StringBuilder badCases = new StringBuilder();
            for (String sc : SETTER_CASES) {
                String outcome = setterCase(f, sc, host, port);
                boolean ok = settersCaseOk(stack, sc, outcome);
                if (!ok) {
                    bad++;
                    badCases.append(badCases.length() == 0 ? "" : ",").append(sc);
                }
                System.out.println("SETTER " + name + " " + sc + " " + (ok ? "ok " : "BAD ") + outcome);
            }
            System.out.println("RESULT " + name + (bad == 0 ? " OK" : " FAIL class=other bad=" + badCases) + " stack="
                    + stack + " cases=" + SETTER_CASES.length + (port == 0 ? " no handshake" : ""));
        } catch (Throwable t) {
            System.out.println("RESULT " + name + " FAIL " + fail(t));
        }
    }

    /** One setters case on a new socket (connected to host:port for the protocol cases unless port is 0). */
    private static String setterCase(SSLSocketFactory f, String sc, String host, int port) throws Exception {
        boolean protocols = isProtocolCase(sc);
        SSLSocket s = (SSLSocket) (protocols && port != 0 ? f.createSocket(host, port) : f.createSocket());
        try {
            String[] enabled;
            try {
                if (sc.equals("rc4")) {
                    s.setEnabledCipherSuites(new String[] {RC4});
                } else if (sc.equals("rc4-mixed")) {
                    s.setEnabledCipherSuites(new String[] {RC4, GCM});
                } else if (sc.equals("tls13-mixed")) {
                    s.setEnabledCipherSuites(new String[] {TLS13_SUITE, GCM});
                } else if (sc.equals("sslv3")) {
                    s.setEnabledProtocols(new String[] {"SSLv3"});
                } else if (sc.equals("mixed-protocols")) {
                    s.setEnabledProtocols(new String[] {"SSLv3", "TLSv1.2"});
                } else {
                    s.setEnabledProtocols(new String[] {"SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2"});
                }
                enabled = protocols ? s.getEnabledProtocols() : s.getEnabledCipherSuites();
            } catch (Exception e) {
                return "throws " + e.getClass().getName() + ": " + String.valueOf(e.getMessage()).replace('\n', ' ');
            }
            String out = "accepted enabled=" + list(enabled);
            if (!protocols) {
                return out;
            }
            if (port == 0) {
                return out + " handshake=none";
            }
            try {
                s.setSoTimeout(20000);
                s.startHandshake();
                SSLSession ss = s.getSession();
                return out + " handshake=OK protocol=" + ss.getProtocol() + " suite=" + ss.getCipherSuite();
            } catch (Throwable t) {
                return out + " handshake=FAIL " + fail(t);
            }
        } finally {
            s.close();
        }
    }

    static boolean isProtocolCase(String sc) {
        return sc.equals("sslv3") || sc.equals("mixed-protocols") || sc.equals("sslv3-plus");
    }

    /** The names in "[a, b]" without the signalling suites (a stack may list them), sorted; null if not a list. */
    static java.util.List<String> names(String bracketed) {
        if (bracketed == null || !bracketed.startsWith("[") || !bracketed.endsWith("]")) {
            return null;
        }
        java.util.List<String> l = new java.util.ArrayList<String>();
        for (String n : bracketed.substring(1, bracketed.length() - 1).split(", ")) {
            if (n.length() > 0 && !n.equals("TLS_EMPTY_RENEGOTIATION_INFO_SCSV") && !n.equals("TLS_FALLBACK_SCSV")) {
                l.add(n);
            }
        }
        java.util.Collections.sort(l);
        return l;
    }

    /**
     * Whether a setters case's outcome is the one expected for the socket's stack (series README "Compatibility",
     * from the Conscrypt 2.5.3 sources: SSLParametersImpl.setEnabledProtocols filters "SSLv3", setEnabledCipherSuites
     * drops TLS 1.3 names and NativeCrypto.checkEnabledCipherSuites throws for any other unsupported name, NativeSsl
     * refuses a handshake with no protocol left; layer A: libcore/0026 keeps RC4 and SSLv3 as opt-ins, 4.4
     * NativeCrypto.checkEnabledCipherSuites throws for the TLS 1.3 name, OpenSSL 1.0.1 ssl23_client_hello sends an
     * SSLv3 hello when TLSv1 is off and SSLv3 on, found on a device). For sslv3-plus Conscrypt may also drop
     * TLSv1/TLSv1.1 (2.6-alpha2 does): any subset of them with TLSv1.2 passes. A stack other than conscrypt or platform
     * is never as expected.
     */
    static boolean settersCaseOk(String stack, String sc, String outcome) {
        boolean threwIae = outcome.startsWith("throws java.lang.IllegalArgumentException");
        if (!outcome.startsWith("accepted enabled=")) {
            if (stack.equals("conscrypt")) {
                return threwIae && (sc.equals("rc4") || sc.equals("rc4-mixed"));
            }
            return stack.equals("platform") && threwIae && sc.equals("tls13-mixed");
        }
        String rest = outcome.substring("accepted enabled=".length());
        int h = rest.indexOf(" handshake=");
        String hs = h < 0 ? null : rest.substring(h + " handshake=".length());
        java.util.List<String> en = names(h < 0 ? rest : rest.substring(0, h));
        if (en == null) {
            return false;
        }
        boolean protocols = isProtocolCase(sc);
        if (protocols != (hs != null)) {
            return false;
        }
        boolean none = "none".equals(hs);
        boolean tls12 = hs != null && hs.startsWith("OK protocol=TLSv1.2 ");
        boolean failed = hs != null && hs.startsWith("FAIL ");
        if (stack.equals("conscrypt")) {
            if (sc.equals("tls13-mixed")) {
                return en.contains(GCM) && !en.contains(RC4);
            }
            if (sc.equals("sslv3")) {
                return en.isEmpty() && (none || failed && hs.indexOf("No enabled protocols") >= 0);
            }
            if (sc.equals("mixed-protocols")) {
                return en.equals(Arrays.asList("TLSv1.2")) && (none || tls12);
            }
            if (sc.equals("sslv3-plus")) {
                return en.contains("TLSv1.2") && Arrays.asList("TLSv1", "TLSv1.1", "TLSv1.2").containsAll(en)
                        && (none || tls12);
            }
            return false;  // rc4, rc4-mixed: Conscrypt must refuse them
        }
        if (stack.equals("platform")) {
            if (sc.equals("rc4")) {
                return en.equals(Arrays.asList(RC4));
            }
            if (sc.equals("rc4-mixed")) {
                return en.equals(Arrays.asList(RC4, GCM));
            }
            if (sc.equals("sslv3")) {
                return en.equals(Arrays.asList("SSLv3")) && (none || failed);
            }
            if (sc.equals("mixed-protocols")) {
                return en.equals(Arrays.asList("SSLv3", "TLSv1.2")) && (none || failed);
            }
            if (sc.equals("sslv3-plus")) {
                return en.equals(Arrays.asList("SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2")) && (none || tls12);
            }
            return false;  // tls13-mixed: the platform has no TLS 1.3 suite
        }
        return false;
    }

    /**
     * An app that bundles org.conscrypt: which copy its class loader returns, whether the boot class loader has any
     * org.conscrypt.Conscrypt (kktls-conscrypt.jar must not be on the boot class path), and what the default factory maps
     * (gate on: the wrapper's own loader with libkktls_conscrypt_jni.so; gate off: nothing). port 0 = no handshake (the
     * default factory's socket is only created). RESULT OK only when the app's own copy is the one returned and the boot
     * loader has none. The probe never loads a Conscrypt library itself: JNI_OnLoad would look up org.conscrypt.NativeCrypto
     * through the probe's loader, which has only the stub, and crash the process (SIGSEGV on the review-1 image).
     */
    private static void shadow(String name, String host, int port) {
        try {
            String gate = "n/a";
            try {
                gate = sysprop(GATE);
            } catch (Throwable t) {
                gate = "n/a (" + describe(t) + ")";
            }
            System.out.println("GATE " + name + " value=\"" + gate + "\"");
            Class<?> c = Class.forName("org.conscrypt.Conscrypt", false, Tls12Probe.class.getClassLoader());
            boolean appCopy = false;
            try {
                c.getField("KKTLS_APP_COPY");
                appCopy = true;
            } catch (NoSuchFieldException e) {
                // only the probe's stub has this field
            }
            String version;
            try {
                version = String.valueOf(c.getMethod("version").invoke(null));
            } catch (Throwable t) {
                version = "n/a (" + describe(t) + ")";
            }
            System.out.println("CLASS " + name + " org.conscrypt.Conscrypt loader=" + c.getClassLoader()
                    + " app-copy=" + appCopy + " version=" + version + " probe-loader="
                    + Tls12Probe.class.getClassLoader());
            boolean bootVisible;
            try {
                Class.forName("org.conscrypt.Conscrypt", false, ClassLoader.getSystemClassLoader().getParent());
                bootVisible = true;
            } catch (ClassNotFoundException e) {
                bootVisible = false;
            }
            System.out.println("BOOT " + name + " org.conscrypt.Conscrypt on the boot class path: " + bootVisible);
            SSLSocketFactory d = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket s = (SSLSocket) d.createSocket();
            s.close();
            String hs = port == 0 ? "no handshake" : handshake(d, host, port);
            System.out.println("MAPS " + name + " after the default factory: " + mapped(SYSTEM_JNI, APP_JNI)
                    + " dex " + mappedContaining("kktls-conscrypt") + " default=" + d);
            System.out.println("RESULT " + name + (appCopy && !bootVisible ? " OK " : " FAIL class=other ") + hs
                    + " app-copy-used=" + appCopy + " boot-visible=" + bootVisible);
        } catch (Throwable t) {
            System.out.println("RESULT " + name + " FAIL " + fail(t));
        }
    }

    /**
     * PSS of this process before and after one TLS use: "url:<url>" (HttpsURLConnection GET), "load" (only the
     * default factory and one unconnected socket: loads the native library) or "local:<host>:<port>:<protos>"
     * (one default-factory handshake restricted to the protocols).
     */
    private static void mem(String name, String mode) {
        System.out.println("PID " + name + " " + android.os.Process.myPid());
        System.out.println("PSS " + name + " before " + pss());
        if (mode.startsWith("url:")) {
            url(name, mode.substring(4));
        } else if (mode.startsWith("local:")) {
            String[] w = mode.split(":");
            csock(name, w[1], Integer.parseInt(w[2]), "default", w[3]);
        } else {
            try {
                SSLSocket s = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket();
                s.close();
                System.out.println("RESULT " + name + " OK loaded " + mapped(SYSTEM_JNI, "libjavacrypto.so"));
            } catch (Throwable t) {
                System.out.println("RESULT " + name + " FAIL " + fail(t));
            }
        }
        System.gc();
        System.out.println("PSS " + name + " after " + pss());
    }

    /** "<path>,<path>" of the mapped files whose names end with one of the given library names. */
    private static String mapped(String... libs) {
        java.util.TreeSet<String> found = new java.util.TreeSet<String>();
        try {
            java.io.BufferedReader r = new java.io.BufferedReader(new java.io.FileReader("/proc/self/maps"));
            try {
                String line;
                while ((line = r.readLine()) != null) {
                    int i = line.indexOf('/');
                    if (i < 0) {
                        continue;
                    }
                    String path = line.substring(i);
                    for (int k = 0; k < libs.length; k++) {
                        if (path.endsWith("/" + libs[k])) {
                            found.add(path);
                        }
                    }
                }
            } finally {
                r.close();
            }
        } catch (java.io.IOException e) {
            return "n/a " + describe(e);
        }
        return found.toString();
    }

    /** "<path>,<path>" of the mapped files whose path contains the given text (e.g. a dalvik-cache file of a jar). */
    private static String mappedContaining(String text) {
        java.util.TreeSet<String> found = new java.util.TreeSet<String>();
        try {
            java.io.BufferedReader r = new java.io.BufferedReader(new java.io.FileReader("/proc/self/maps"));
            try {
                String line;
                while ((line = r.readLine()) != null) {
                    int i = line.indexOf('/');
                    if (i >= 0 && line.substring(i).indexOf(text) >= 0) {
                        found.add(line.substring(i));
                    }
                }
            } finally {
                r.close();
            }
        } catch (java.io.IOException e) {
            return "n/a " + describe(e);
        }
        return found.toString();
    }

    /** Total PSS of this process and of the TLS-related mappings, in kB, from /proc/self/smaps. */
    private static String pss() {
        String[] keys = {SYSTEM_JNI, "kktls-conscrypt", "kktls-sslfactory", "libjavacrypto.so", "libssl.so",
                "libcrypto.so", "dalvik-heap", "core.jar", "conscrypt.jar"};
        long[] per = new long[keys.length];
        long total = 0;
        try {
            java.io.BufferedReader r = new java.io.BufferedReader(new java.io.FileReader("/proc/self/smaps"));
            String line;
            String cur = "";
            try {
                while ((line = r.readLine()) != null) {
                    if (line.matches("^[0-9a-f]+-[0-9a-f]+ .*")) {
                        String[] w = line.trim().split("\\s+", 6);
                        cur = w.length == 6 ? w[5] : "";
                    } else if (line.startsWith("Pss:")) {
                        long kb = Long.parseLong(line.replaceAll("[^0-9]", ""));
                        total += kb;
                        for (int k = 0; k < keys.length; k++) {
                            if (cur.indexOf(keys[k]) >= 0) {
                                per[k] += kb;
                            }
                        }
                    }
                }
            } finally {
                r.close();
            }
        } catch (Exception e) {
            return "n/a " + describe(e);
        }
        StringBuilder sb = new StringBuilder("total=" + total + "kB");
        for (int k = 0; k < keys.length; k++) {
            sb.append(' ').append(keys[k]).append('=').append(per[k]);
        }
        return sb.toString();
    }

    private static void apache(String name, String u) {
        long t0 = System.currentTimeMillis();
        org.apache.http.impl.client.DefaultHttpClient client = new org.apache.http.impl.client.DefaultHttpClient();
        try {
            org.apache.http.params.HttpConnectionParams.setConnectionTimeout(client.getParams(), 20000);
            org.apache.http.params.HttpConnectionParams.setSoTimeout(client.getParams(), 20000);
            org.apache.http.HttpResponse r = client.execute(new org.apache.http.client.methods.HttpGet(u));
            int code = r.getStatusLine().getStatusCode();
            String body = r.getEntity() == null ? "" : readSome(r.getEntity().getContent(), 16384);
            System.out.println("BODY " + name + " " + body.replace('\n', ' '));
            System.out.println("RESULT " + name + " OK code=" + code + " ms=" + (System.currentTimeMillis() - t0));
        } catch (Throwable t) {
            System.out.println("RESULT " + name + " FAIL " + fail(t) + " ms=" + (System.currentTimeMillis() - t0));
        } finally {
            client.getConnectionManager().shutdown();
        }
    }

    private static String readSome(InputStream in, int max) throws Exception {
        if (in == null) {
            return "";
        }
        try {
            byte[] buf = new byte[max];
            int n = 0;
            int r;
            while (n < max && (r = in.read(buf, n, max - n)) > 0) {
                n += r;
            }
            return new String(buf, 0, n, "UTF-8");
        } finally {
            in.close();
        }
    }

    /** "class=<c> <describe(t)>", the text after "FAIL" in a RESULT line. */
    private static String fail(Throwable t) {
        return "class=" + classify(t) + " " + describe(t);
    }

    /**
     * The failure class of a refused or failed connection, from the whole cause chain, first match wins:
     * cert (CertificateException / CertPathValidatorException / CertPathBuilderException anywhere: trust anchor, expiry,
     * self-signed), network (no TLS evidence: UnknownHost, SocketTimeout, any SocketException -- Connect, NoRouteToHost,
     * PortUnreachable, a reset -- or EOFException anywhere in the chain, also when an SSLException wraps it; or the 4.4
     * NativeCrypto texts of a connection lost without an alert, "Connection closed by peer" and "I/O error during
     * system call" (SSL_ERROR_SYSCALL), which carry no Java cause; before the name check, since a DNS failure says "No
     * address associated with hostname"), hostname (a message about the host name: okhttp "Hostname ... not
     * verified", Apache "hostname in certificate didn't match", SSLCertificateSocketFactory "Cannot verify hostname"),
     * handshake (any other SSLException: alert, protocol or cipher refusal), else other. The matrix accepts a FAIL row
     * only for its expected class, never for network.
     */
    static String classify(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof java.security.cert.CertificateException
                    || c instanceof java.security.cert.CertPathValidatorException
                    || c instanceof java.security.cert.CertPathBuilderException) {
                return "cert";
            }
        }
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof java.net.UnknownHostException || c instanceof java.net.SocketTimeoutException
                    || c instanceof java.net.SocketException || c instanceof java.io.EOFException) {
                return "network";
            }
            String m = String.valueOf(c.getMessage()).toLowerCase(java.util.Locale.US);
            if (m.indexOf("connection closed by peer") >= 0 || m.indexOf("i/o error during system call") >= 0) {
                return "network";
            }
        }
        for (Throwable c = t; c != null; c = c.getCause()) {
            String m = String.valueOf(c.getMessage()).toLowerCase(java.util.Locale.US);
            if (m.indexOf("hostname") >= 0 || m.indexOf("host name") >= 0) {
                return "hostname";
            }
        }
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof javax.net.ssl.SSLException) {
                return "handshake";
            }
        }
        return "other";
    }

    /** t0 with t1 as its cause, t1 with t2, ...; returns t0. */
    private static Throwable chain(Throwable... ts) {
        for (int i = 0; i + 1 < ts.length; i++) {
            ts[i].initCause(ts[i + 1]);
        }
        return ts[0];
    }

    /** classify() on synthetic cause chains shaped like the 4.4 platform's and Conscrypt's exceptions. */
    static int selftest() {
        String alert = "SSL handshake aborted: ssl=0x1: Failure in SSL library, usually a protocol error error:14077410:"
                + "SSL routines:SSL23_GET_SERVER_HELLO:sslv3 alert handshake failure";
        Object[][] cases = {
            {"platform alert", "handshake", chain(new javax.net.ssl.SSLHandshakeException("javax.net.ssl."
                    + "SSLProtocolException: " + alert), new javax.net.ssl.SSLProtocolException(alert))},
            {"inappropriate_fallback alert", "handshake", new javax.net.ssl.SSLHandshakeException(
                    "error:1407743E:SSL routines:SSL23_GET_SERVER_HELLO:tlsv1 alert inappropriate fallback")},
            {"reset wrapped in SSLHandshakeException", "network", chain(new javax.net.ssl.SSLHandshakeException(
                    "Read error"), new java.net.SocketException("Connection reset"))},
            {"EOF wrapped in SSLException", "network", chain(new javax.net.ssl.SSLException("Read error"),
                    new java.io.EOFException())},
            {"4.4 SSL_ERROR_SYSCALL text, no cause", "network", new javax.net.ssl.SSLHandshakeException(
                    "javax.net.ssl.SSLProtocolException: SSL handshake aborted: ssl=0x1: I/O error during system call,"
                    + " Connection reset by peer")},
            {"4.4 clean close text, no cause", "network", chain(new javax.net.ssl.SSLHandshakeException(
                    "javax.net.ssl.SSLException: Connection closed by peer"),
                    new javax.net.ssl.SSLException("Connection closed by peer"))},
            {"connect refused", "network", new java.net.ConnectException("failed to connect: ECONNREFUSED")},
            {"timeout", "network", new java.net.SocketTimeoutException("SSL handshake timed out")},
            {"DNS (says hostname)", "network", chain(new java.net.UnknownHostException(
                    "Unable to resolve host \"x\": No address associated with hostname"))},
            {"untrusted chain", "cert", chain(new javax.net.ssl.SSLHandshakeException("x"),
                    new java.security.cert.CertificateException("y"),
                    new java.security.cert.CertPathValidatorException("Trust anchor for certification path not found."))},
            {"certificate failure after a reset text", "cert", chain(new javax.net.ssl.SSLHandshakeException(
                    "Connection closed by peer"), new java.security.cert.CertificateException("expired"))},
            {"SSLCertificateSocketFactory name check", "hostname",
                    new javax.net.ssl.SSLPeerUnverifiedException("Cannot verify hostname: wrong.host.badssl.com")},
            {"okhttp name check", "hostname", new java.io.IOException("Hostname 'x' was not verified")},
            {"no TLS involved", "other", new IllegalStateException("x")},
        };
        int bad = 0;
        for (Object[] c : cases) {
            String got = classify((Throwable) c[2]);
            boolean ok = got.equals(c[1]);
            bad += ok ? 0 : 1;
            System.out.println("selftest " + (ok ? "ok   " : "FAIL ") + c[0] + ": " + got + (ok ? "" : ", want " + c[1]));
        }
        // both (review 3, codex 5): the verdict needs positive evidence that the default step used Conscrypt
        String sysLoader = "dalvik.system.PathClassLoader[DexPathList[[zip file \"/system/framework/kktls-conscrypt.jar\"],"
                + "nativeLibraryDirectories=[/system/lib]]]";
        String app = "dalvik.system.PathClassLoader[DexPathList[[zip file \"/data/local/tmp/kktlsapp/app.jar\"]]]";
        String boot = "java.lang.BootClassLoader@1";
        Object[][] origins = {
            {"wrapper's Conscrypt socket", "org.conscrypt.KitKatPlatformOpenSSLSocketImplAdapter", sysLoader, false, "conscrypt"},
            {"platform socket", "com.android.org.conscrypt.OpenSSLSocketImpl", boot, true, "platform"},
            {"an app's own Conscrypt socket", "org.conscrypt.KitKatPlatformOpenSSLSocketImplAdapter", app, false, "other"},
            {"a platform class name from another loader", "com.android.org.conscrypt.OpenSSLSocketImpl", sysLoader, false,
                    "other"},
            {"JB platform socket", "org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl", boot, true, "platform"},
            {"JB platform socket wrapper", "org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImplWrapper", boot, true,
                    "platform"},
            {"a JB platform class name from an app's loader", "org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl",
                    app, false, "other"},
            {"harmony's pure-Java SSLSocketImpl", "org.apache.harmony.xnet.provider.jsse.SSLSocketImpl", boot, true,
                    "other"},
        };
        for (Object[] c : origins) {
            String got = socketOrigin((String) c[1], (String) c[2], ((Boolean) c[3]).booleanValue());
            boolean ok = got.equals(c[4]);
            bad += ok ? 0 : 1;
            System.out.println("selftest " + (ok ? "ok   " : "FAIL ") + "socketOrigin " + c[0] + ": " + got
                    + (ok ? "" : ", want " + c[4]));
        }
        String maps = "[/system/lib/libcrypto.so, /system/lib/libjavacrypto.so, /system/lib/libkktls_conscrypt_jni.so,"
                + " /system/lib/libssl.so]";
        String cons = "io.github.hsw.kktls.KktlsDefaultSSLSocketFactory@1 [conscrypt: x]";
        String fell = "io.github.hsw.kktls.KktlsDefaultSSLSocketFactory@1 [platform: Conscrypt is not usable]";
        // 4.1-4.3 (jb): NativeCrypto is in libjavacore.so, which links libssl/libcrypto and every Dalvik process maps,
        // so only the Conscrypt library is checked there
        String jbMaps = "[/system/lib/libcrypto.so, /system/lib/libjavacore.so, /system/lib/libkktls_conscrypt_jni.so,"
                + " /system/lib/libssl.so]";
        Object[][] verdicts = {
            {"both stacks", true, cons, "conscrypt", "platform", maps, false, true},
            {"wrapper fell back after loading its library (two platform handshakes)", true, fell, "platform",
                    "platform", maps, false, false},
            {"default factory says Conscrypt, its socket is the platform's", true, cons, "platform", "platform", maps,
                    false, false},
            {"default step from an app's Conscrypt", true, cons, "other", "platform", maps, false, false},
            {"platform step not from the platform", true, cons, "conscrypt", "conscrypt", maps, false, false},
            {"a step failed", false, cons, "conscrypt", "none", maps, false, false},
            {"Conscrypt library not mapped", true, cons, "conscrypt", "platform",
                    "[/system/lib/libjavacrypto.so]", false, false},
            {"4.4: libssl.so without libjavacrypto.so", true, cons, "conscrypt", "platform", jbMaps, false, false},
            {"JB both stacks", true, cons, "conscrypt", "platform", jbMaps, true, true},
            {"JB wrapper fell back (two platform handshakes)", true, fell, "platform", "platform", jbMaps, true, false},
            {"JB platform step not from the platform", true, cons, "conscrypt", "other", jbMaps, true, false},
            {"JB Conscrypt library not mapped", true, cons, "conscrypt", "platform", "[/system/lib/libcrypto.so,"
                    + " /system/lib/libjavacore.so, /system/lib/libssl.so]", true, false},
        };
        for (Object[] c : verdicts) {
            boolean got = bothVerdict(((Boolean) c[1]).booleanValue(), (String) c[2], (String) c[3], (String) c[4],
                    (String) c[5], ((Boolean) c[6]).booleanValue());
            boolean ok = got == ((Boolean) c[7]).booleanValue();
            bad += ok ? 0 : 1;
            System.out.println("selftest " + (ok ? "ok   " : "FAIL ") + "bothVerdict " + c[0] + ": " + got
                    + (ok ? "" : ", want " + c[7]));
        }
        // setters (post-EOL plan Task 9): the expected outcome per stack; the other stack's outcome must not pass
        String iae = "throws java.lang.IllegalArgumentException: cipherSuite " + RC4 + " is not supported.";
        String tls12ok = " handshake=OK protocol=TLSv1.2 suite=" + GCM;
        String sslv3Fail = " handshake=FAIL class=handshake javax.net.ssl.SSLHandshakeException: No enabled protocols;"
                + " SSLv3 is no longer supported and was filtered from the list";
        String alertFail = " handshake=FAIL class=handshake javax.net.ssl.SSLHandshakeException: alert protocol version";
        Object[][] setters = {
            {"conscrypt rc4 throws", "conscrypt", "rc4", iae, true},
            {"conscrypt rc4 accepted (layer A behaviour)", "conscrypt", "rc4", "accepted enabled=[" + RC4 + "]", false},
            {"conscrypt rc4-mixed throws (no filtering)", "conscrypt", "rc4-mixed", iae, true},
            {"conscrypt rc4-mixed filtered to GCM", "conscrypt", "rc4-mixed", "accepted enabled=[" + GCM + "]", false},
            {"conscrypt tls13-mixed keeps GCM", "conscrypt", "tls13-mixed", "accepted enabled=[TLS_AES_128_GCM_SHA256,"
                    + " TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, " + GCM + "]", true},
            {"conscrypt tls13-mixed throws", "conscrypt", "tls13-mixed", "throws java.lang.IllegalArgumentException: x",
                    false},
            {"conscrypt sslv3 filtered, handshake refused", "conscrypt", "sslv3", "accepted enabled=[]" + sslv3Fail,
                    true},
            {"conscrypt sslv3 filtered, no handshake", "conscrypt", "sslv3", "accepted enabled=[] handshake=none", true},
            {"conscrypt sslv3 kept (layer A behaviour)", "conscrypt", "sslv3", "accepted enabled=[SSLv3]" + alertFail,
                    false},
            {"conscrypt sslv3 failed for another reason", "conscrypt", "sslv3", "accepted enabled=[] handshake=FAIL"
                    + " class=network java.net.SocketException: Connection reset", false},
            {"conscrypt sslv3 handshake OK", "conscrypt", "sslv3", "accepted enabled=[]" + tls12ok, false},
            {"conscrypt mixed-protocols filtered, TLSv1.2", "conscrypt", "mixed-protocols", "accepted enabled=[TLSv1.2]"
                    + tls12ok, true},
            {"conscrypt mixed-protocols kept SSLv3", "conscrypt", "mixed-protocols", "accepted enabled=[SSLv3, TLSv1.2]"
                    + tls12ok, false},
            {"conscrypt mixed-protocols, handshake failed", "conscrypt", "mixed-protocols", "accepted enabled=[TLSv1.2]"
                    + alertFail, false},
            {"conscrypt protocol case without its handshake part", "conscrypt", "mixed-protocols",
                    "accepted enabled=[TLSv1.2]", false},
            {"platform rc4 accepted", "platform", "rc4", "accepted enabled=[" + RC4 + "]", true},
            {"platform rc4 throws (layer D behaviour)", "platform", "rc4", iae, false},
            {"platform rc4-mixed keeps both", "platform", "rc4-mixed", "accepted enabled=[" + GCM + ", " + RC4 + "]",
                    true},
            {"platform rc4-mixed lost RC4", "platform", "rc4-mixed", "accepted enabled=[" + GCM + "]", false},
            {"platform tls13-mixed throws", "platform", "tls13-mixed", "throws java.lang.IllegalArgumentException:"
                    + " cipherSuite TLS_AES_128_GCM_SHA256 is not supported.", true},
            {"platform tls13-mixed accepted", "platform", "tls13-mixed", "accepted enabled=[" + GCM + "]", false},
            {"platform sslv3 kept, handshake refused", "platform", "sslv3", "accepted enabled=[SSLv3]" + alertFail, true},
            {"platform sslv3 kept, SCSV listed too", "platform", "sslv3", "accepted enabled=[SSLv3, TLS_FALLBACK_SCSV]"
                    + " handshake=none", true},
            {"platform sslv3 handshake OK", "platform", "sslv3", "accepted enabled=[SSLv3] handshake=OK protocol=SSLv3"
                    + " suite=x", false},
            {"platform sslv3 filtered (layer D behaviour)", "platform", "sslv3", "accepted enabled=[]" + sslv3Fail,
                    false},
            {"platform mixed-protocols keeps SSLv3, TLSv1.2, SSLv3 hello refused", "platform", "mixed-protocols",
                    "accepted enabled=[SSLv3, TLSv1.2]" + alertFail, true},
            {"platform mixed-protocols, TLSv1.2 handshake (not OpenSSL 1.0.1)", "platform", "mixed-protocols",
                    "accepted enabled=[SSLv3, TLSv1.2]" + tls12ok, false},
            {"platform mixed-protocols filtered", "platform", "mixed-protocols", "accepted enabled=[TLSv1.2]" + tls12ok,
                    false},
            {"platform sslv3-plus keeps all four, TLSv1.2", "platform", "sslv3-plus",
                    "accepted enabled=[SSLv3, TLSv1, TLSv1.1, TLSv1.2]" + tls12ok, true},
            {"platform sslv3-plus filtered", "platform", "sslv3-plus", "accepted enabled=[TLSv1, TLSv1.1, TLSv1.2]"
                    + tls12ok, false},
            {"conscrypt 2.5.3 sslv3-plus filters SSLv3", "conscrypt", "sslv3-plus",
                    "accepted enabled=[TLSv1, TLSv1.1, TLSv1.2]" + tls12ok, true},
            {"conscrypt 2.6-alpha2 sslv3-plus keeps only TLSv1.2", "conscrypt", "sslv3-plus",
                    "accepted enabled=[TLSv1.2]" + tls12ok, true},
            {"conscrypt sslv3-plus kept SSLv3", "conscrypt", "sslv3-plus",
                    "accepted enabled=[SSLv3, TLSv1, TLSv1.1, TLSv1.2]" + tls12ok, false},
            {"conscrypt sslv3-plus, handshake failed", "conscrypt", "sslv3-plus",
                    "accepted enabled=[TLSv1, TLSv1.1, TLSv1.2]" + alertFail, false},
            {"setter threw something else", "conscrypt", "rc4", "throws java.lang.NullPointerException: x", false},
            {"other stack", "other", "rc4", iae, false},
        };
        for (Object[] c : setters) {
            boolean got = settersCaseOk((String) c[1], (String) c[2], (String) c[3]);
            boolean ok = got == ((Boolean) c[4]).booleanValue();
            bad += ok ? 0 : 1;
            System.out.println("selftest " + (ok ? "ok   " : "FAIL ") + "settersCaseOk " + c[0] + ": " + got
                    + (ok ? "" : ", want " + c[4]));
        }
        int n = cases.length + origins.length + verdicts.length + setters.length;
        System.out.println("SELFTEST " + (bad == 0 ? "PASS" : "FAIL") + " (" + n + " cases)");
        return bad == 0 ? 0 : 1;
    }

    private static String describe(Throwable t) {
        StringBuilder sb = new StringBuilder();
        Throwable c = t;
        int depth = 0;
        while (c != null && depth < 4) {
            if (depth > 0) {
                sb.append(" <- ");
            }
            sb.append(c.getClass().getName()).append(": ").append(String.valueOf(c.getMessage()).replace('\n', ' '));
            c = c.getCause();
            depth++;
        }
        return sb.toString();
    }
}
