// SPDX-License-Identifier: Apache-2.0
/*
 * Host test (JUnit 3.8.2 on a host JDK, run-host-tests.sh) of io.github.hsw.kktls.KktlsDefaultSSLSocketFactory, the
 * default SSLSocketFactory of the series (libcore): standalone Conscrypt when layer D is installed, the platform factory
 * otherwise, and the kill switch persist.kktls.conscrypt ("0" = layer A even when installed).
 *
 * Each test loads the wrapper in a fresh child class loader (one loader = one process) that holds the wrapper classes
 * plus the stubs the case needs (stub-android: android.os.SystemProperties, value from -Dkktlstest.gate; stub-platform:
 * com.android.org.conscrypt.OpenSSLSocketFactoryImpl; stub-dalvik: dalvik.system.PathClassLoader, present unless the
 * case says "nodalvik"), so static state (the kill-switch read, the installed check, the log-once flag, the per-process
 * Conscrypt loader and provider, a failed class initializer) never leaks between cases, and a missing stub is a missing
 * class exactly as on a device whose kktls-conscrypt.jar lacks it (or a VM without the framework). Conscrypt
 * (stub-conscrypt: org.conscrypt.Conscrypt) is never on the wrapper's own path, as on the device, where
 * kktls-conscrypt.jar is not on the boot class path: the case "conscrypt" installs it as the "jar" that the stub
 * PathClassLoader serves (-Dkktlstest.jar). Whether layer D is installed is a real file: run-host-tests.sh compiles the
 * wrapper with SYSTEM_ROOT = -Dkktlstest.system, setUp creates <root>/framework/kktls-conscrypt.jar there (installed),
 * and uninstall() deletes it.
 * The wrapper's loader records every class name it is asked for (the PathClassLoader is parent-first, so its lookups
 * land there too), so an off case can prove that no org.conscrypt class and no PathClassLoader was even looked up
 * (on the device that lookup is what opens the jar and libkktls_conscrypt_jni.so). setUp sets the property to "1";
 * the kill-switch tests change it. jsse.enableSNIExtension is cleared before and after every case (SNI guard).
 * The NEON check reads <proc>/self/auxv and <proc>/cpuinfo (run-host-tests.sh compiles PROC_ROOT = -Dkktlstest.proc):
 * install() writes an auxv with HWCAP_NEON and no cpuinfo, the NEON cases change them. The Jelly Bean shape is
 * stub-platform-jb (org.apache.harmony.xnet.provider.jsse.OpenSSLSocketFactoryImpl instead of stub-platform) and, with
 * -Dkktlstest.mode=adapter, Conscrypt's KitKat adapter factory without stub-kitkat (no
 * com.android.org.conscrypt.OpenSSLSocketImpl): the wrapper must take the adapter's inner factory there, and keep the
 * adapter with stub-kitkat (4.4).
 * This class never names the wrapper at compile time.
 * The host JDK proves behaviour, not Java 6 source compatibility: that proof is the KitKat build of libcore.
 */
package kktlstest;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocketFactory;
import junit.framework.TestCase;

public class KktlsDefaultSSLSocketFactoryTest extends TestCase {
    static final String WRAPPER = "io.github.hsw.kktls.KktlsDefaultSSLSocketFactory";
    /** The SSLv3-filtering wrapper socket (kktls-sslfilter.jar) the factory puts around Conscrypt sockets; the factory
     *  names it only as a string and loads it from the Conscrypt loader, so the test never references it at compile. */
    static final String FILTER_SOCKET_CLASS = "org.conscrypt.KktlsFilteringSSLSocket";
    static final String LOG_TAG = "KktlsSslFactory";
    static final String GATE_PROPERTY = "persist.kktls.conscrypt";
    /** The one read of the kill switch: SystemProperties.get(GATE_PROPERTY, "") (recorded by stub-android). */
    static final String GATE_READ = "props:get(" + GATE_PROPERTY + ",)";
    /** The wrapper's SYSTEM_ROOT in this run ("/system" on a device; run-host-tests.sh compiles a temp dir in). */
    static final String ROOT = System.getProperty("kktlstest.system", "<run through run-host-tests.sh>");
    /** The file whose presence means "layer D installed". */
    static final File INSTALLED_JAR = new File(ROOT + "/framework/kktls-conscrypt.jar");
    /** libkktls_conscrypt_jni.so: the wrapper checks its ELF header before it creates the loader (truncated = SIGBUS
     *  in the 4.4 linker); install() writes a valid fixture, the library cases replace it. */
    static final File LIBRARY = new File(ROOT + "/lib/libkktls_conscrypt_jni.so");
    static final int EM_ARM = 40;
    /** The wrapper's PROC_ROOT in this run ("/proc" on a device). */
    static final String PROC = System.getProperty("kktlstest.proc", "<run through run-host-tests.sh>");
    static final File AUXV = new File(PROC + "/self/auxv");
    static final File CPUINFO = new File(PROC + "/cpuinfo");
    /** AT_HWCAP of the 4.3 ARM emulator with a NEON kernel, and the same without HWCAP_NEON (the SDK API 16-18 kernels). */
    static final long HWCAP_WITH_NEON = 0x2fb0d7L;
    static final long HWCAP_WITHOUT_NEON = 0x2fa0d7L;
    static final int EM_386 = 3;
    /** The wrapper's own loader for Conscrypt + the SSLv3-filtering wrapper socket: both installed jars, <root>/lib,
     *  parent = the wrapper's loader. The dexPath joins the two with the platform path separator. */
    static final String CONSCRYPT_LOADER = "dalvik:new(" + ROOT + "/framework/kktls-conscrypt.jar" + File.pathSeparator
            + ROOT + "/framework/kktls-sslfilter.jar," + ROOT + "/lib,RecordingLoader)";
    /** Conscrypt.newProvider(): alpha2's Android defaults (TLS 1.2/1.3 only), so the wrapper must never call it. */
    static final String NEW_PROVIDER = "conscrypt:newProvider";
    /** The provider build with TLS 1.0/1.1 back on (review of Tasks 10-12): the flags the stub builds with. */
    static final String BUILD = "conscrypt:build(deprecated=false,enabled=true)";
    /** newProviderBuilder().isTlsV1Deprecated(false).isTlsV1Enabled(true).build(), in this order. */
    static final List<String> PROVIDER_CALLS = Collections.unmodifiableList(Arrays.asList(
            "conscrypt:newProviderBuilder", "conscrypt:isTlsV1Deprecated(false)", "conscrypt:isTlsV1Enabled(true)",
            BUILD));
    static final String INIT = "conscrypt:init(null,null,null)";
    /** The whole Conscrypt path of one first construction. */
    static final List<String> CONSCRYPT_PATH;
    static {
        List<String> l = new ArrayList<String>();
        l.add(GATE_READ);
        l.add(CONSCRYPT_LOADER);
        l.addAll(PROVIDER_CALLS);
        l.add(INIT);
        CONSCRYPT_PATH = Collections.unmodifiableList(l);
    }
    /** Conscrypt 2.5.3 throws from every handshake unless this is unset, "true" or "false" (any case). */
    static final String SNI_PROPERTY = "jsse.enableSNIExtension";
    /** Held strongly: Logger.getLogger keeps only a weak reference, so GC could drop the handler between calls. */
    private static final Logger LOG = Logger.getLogger(LOG_TAG);

    /**
     * The public methods of javax.net.SocketFactory + javax.net.ssl.SSLSocketFactory in Android 4.4 that a factory
     * must implement, pinned by hand: the Mac JDK's SSLSocketFactory has more (createSocket(Socket, InputStream,
     * boolean), Java 8 / API 24), which 4.4 lacks. createSocket() is not abstract, but its SocketFactory default
     * throws, and the 4.4 OpenSSLSocketFactoryImpl overrides it, so the wrapper must delegate it too.
     */
    static final String[] API_44 = {
        "getDefaultCipherSuites()",
        "getSupportedCipherSuites()",
        "createSocket()",
        "createSocket(java.net.Socket,java.lang.String,int,boolean)",
        "createSocket(java.lang.String,int)",
        "createSocket(java.lang.String,int,java.net.InetAddress,int)",
        "createSocket(java.net.InetAddress,int)",
        "createSocket(java.net.InetAddress,int,java.net.InetAddress,int)",
    };

    private final List<LogRecord> records = new ArrayList<LogRecord>();
    private final Handler handler = new Handler() {
        @Override public void publish(LogRecord r) { records.add(r); }
        @Override public void flush() {}
        @Override public void close() {}
    };

    /** A loader that records the name of every class it is asked for (Class.forName from the wrapper lands here). */
    static final class RecordingLoader extends URLClassLoader {
        final List<String> requested = new ArrayList<String>();

        RecordingLoader(URL[] urls, ClassLoader parent) {
            super(urls, parent);
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            synchronized (requested) {
                requested.add(name);
            }
            return super.loadClass(name, resolve);
        }

        /** The requested names in org.conscrypt (Conscrypt 2.5.3), not com.android.org.conscrypt (the platform). */
        List<String> conscryptLookups() {
            List<String> out = new ArrayList<String>();
            synchronized (requested) {
                for (String n : requested) {
                    if (n.startsWith("org.conscrypt.")) {
                        out.add(n);
                    }
                }
            }
            return out;
        }
    }

    @Override
    protected void setUp() throws Exception {
        install();
        RecordingSSLSocketFactory.reset();
        records.clear();
        System.clearProperty("kktlstest.mode");
        System.clearProperty("kktlstest.platform");
        System.clearProperty("kktlstest.jar");
        System.setProperty("kktlstest.gate", "1");
        System.clearProperty(SNI_PROPERTY);
        LOG.addHandler(handler);
        LOG.setUseParentHandlers(false); // keep the expected warnings off the console
    }

    @Override
    protected void tearDown() throws Exception {
        install();
        LOG.removeHandler(handler);
        LOG.setUseParentHandlers(true);
        System.clearProperty("kktlstest.jar");
        System.clearProperty("kktlstest.mode");
        System.clearProperty("kktlstest.platform");
        System.clearProperty("kktlstest.gate");
        System.clearProperty(SNI_PROPERTY);
    }

    /** Layer D installed: <root>/framework/kktls-conscrypt.jar exists (its content is never read: the stub
     *  PathClassLoader serves the classes), and <root>/lib/libkktls_conscrypt_jni.so is a valid ARM ELF fixture. */
    static void install() throws IOException {
        assertNotNull("run through run-host-tests.sh: -Dkktlstest.system is not set", System.getProperty("kktlstest.system"));
        File d = INSTALLED_JAR.getParentFile();
        assertTrue("cannot create " + d, d.isDirectory() || d.mkdirs());
        assertTrue("cannot create " + INSTALLED_JAR, INSTALLED_JAR.isFile() || INSTALLED_JAR.createNewFile());
        writeLibrary(elf(EM_ARM, 8192));
        writeAuxv(HWCAP_WITH_NEON);
        writeCpuinfo(null);
    }

    /** A 32-bit auxv: AT_PHDR, AT_PAGESZ, then AT_HWCAP = hwcap unless null, AT_NULL. null hwcap and no file: -1. */
    static void writeAuxv(Long hwcap) throws IOException {
        File d = AUXV.getParentFile();
        assertTrue("cannot create " + d, d.isDirectory() || d.mkdirs());
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        long[] entries = hwcap == null ? new long[] {3, 0x8034, 6, 4096, 0, 0}
                : new long[] {3, 0x8034, 6, 4096, 16, hwcap, 0, 0};
        for (long v : entries) {
            byte[] w = new byte[4];
            le(w, 0, v, 4);
            b.write(w);
        }
        write(AUXV, b.toByteArray());
    }

    static void deleteAuxv() {
        assertTrue("cannot delete " + AUXV, !AUXV.exists() || AUXV.delete());
    }

    /** /proc/cpuinfo with this Features line (null: no file). */
    static void writeCpuinfo(String features) throws IOException {
        if (features == null) {
            assertTrue("cannot delete " + CPUINFO, !CPUINFO.exists() || CPUINFO.delete());
            return;
        }
        write(CPUINFO, ("Processor\t: ARMv7 Processor rev 0 (v7l)\nBogoMIPS\t: 12.00\nFeatures\t: " + features
                + "\nCPU implementer\t: 0x41\n\nHardware\t: Goldfish\n").getBytes("ISO-8859-1"));
    }

    static void write(File f, byte[] content) throws IOException {
        FileOutputStream out = new FileOutputStream(f);
        try {
            out.write(content);
        } finally {
            out.close();
        }
    }

    static void writeLibrary(byte[] content) throws IOException {
        File d = LIBRARY.getParentFile();
        assertTrue("cannot create " + d, d.isDirectory() || d.mkdirs());
        FileOutputStream out = new FileOutputStream(LIBRARY);
        try {
            out.write(content);
        } finally {
            out.close();
        }
    }

    /**
     * A minimal 32-bit little-endian ET_DYN ELF of {@code size} (> 4096) bytes for {@code machine}: three program
     * headers, a PT_PHDR (not a load segment), PT_LOAD [0, 4096) and PT_LOAD [4096, size), so the last segment ends
     * exactly at the end of the file. The first 4096 bytes are what the device repro left (dd bs=4096 count=1).
     */
    static byte[] elf(int machine, int size) {
        byte[] b = new byte[size];
        b[0] = 0x7f;
        b[1] = 'E';
        b[2] = 'L';
        b[3] = 'F';
        b[4] = 1; // ELFCLASS32
        b[5] = 1; // ELFDATA2LSB
        b[6] = 1; // EV_CURRENT
        le(b, 16, 3, 2); // e_type ET_DYN
        le(b, 18, machine, 2);
        le(b, 20, 1, 4); // e_version
        le(b, 28, 52, 4); // e_phoff
        le(b, 40, 52, 2); // e_ehsize
        le(b, 42, 32, 2); // e_phentsize
        le(b, 44, 3, 2); // e_phnum
        phdr(b, 0, 6, 52, 96); // PT_PHDR
        phdr(b, 1, 1, 0, 4096); // PT_LOAD
        phdr(b, 2, 1, 4096, size - 4096); // PT_LOAD, ends at EOF
        return b;
    }

    static void phdr(byte[] b, int i, long type, long offset, long filesz) {
        int o = 52 + 32 * i;
        le(b, o, type, 4);
        le(b, o + 4, offset, 4);
        le(b, o + 16, filesz, 4);
        le(b, o + 20, filesz, 4); // p_memsz
    }

    static void le(byte[] b, int o, long v, int n) {
        for (int i = 0; i < n; i++) {
            b[o + i] = (byte) (v >>> (8 * i));
        }
    }

    /** Layer D not installed: the jar does not exist. */
    static void uninstall() {
        assertTrue("cannot delete " + INSTALLED_JAR, !INSTALLED_JAR.exists() || INSTALLED_JAR.delete());
    }

    private static URL dir(String property) throws Exception {
        String p = System.getProperty(property);
        assertNotNull("run through run-host-tests.sh: -D" + property + " is not set", p);
        File f = new File(p);
        assertTrue(f + " is not a directory", f.isDirectory());
        return f.toURI().toURL();
    }

    /**
     * A fresh loader (a new "process"): the wrapper plus the given stubs ("android", "platform") and stub-dalvik
     * (unless "nodalvik"), parent = this test's loader. "conscrypt" does not go on this path: it installs the jar that
     * the stub PathClassLoader serves (-Dkktlstest.jar), as kktls-conscrypt.jar in /system/framework off the boot class
     * path. Whether the jar file exists is install()/uninstall().
     */
    private static RecordingLoader loader(String... stubs) throws Exception {
        List<URL> urls = new ArrayList<URL>();
        urls.add(dir("kktlstest.wrapper"));
        List<String> list = Arrays.asList(stubs);
        if (!list.contains("nodalvik")) {
            urls.add(dir("kktlstest.stub.dalvik"));
        }
        System.clearProperty("kktlstest.jar");
        for (String s : stubs) {
            if (s.equals("conscrypt") || s.equals("conscrypt253")) {
                System.setProperty("kktlstest.jar", new File(dir("kktlstest.stub." + s).toURI()).getPath());
            } else if (!s.equals("nodalvik")) {
                urls.add(dir("kktlstest.stub." + s));
            }
        }
        return new RecordingLoader(urls.toArray(new URL[0]), KktlsDefaultSSLSocketFactoryTest.class.getClassLoader());
    }

    private static int count(List<String> calls, String call) {
        int n = 0;
        for (String c : calls) {
            n += c.equals(call) ? 1 : 0;
        }
        return n;
    }

    /** new KktlsDefaultSSLSocketFactory() in that loader, the way SSLSocketFactory.getDefault() does it. */
    private static SSLSocketFactory newWrapper(ClassLoader cl) throws Throwable {
        Class<?> c = Class.forName(WRAPPER, true, cl);
        assertTrue("the wrapper is public", Modifier.isPublic(c.getModifiers()));
        try {
            return (SSLSocketFactory) c.getConstructor().newInstance();
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    private void assertDelegatesTo(String origin, SSLSocketFactory f) throws Exception {
        assertDelegatesTo(origin, origin, f);
    }

    /** One call reaches the stub factory named origin; toString() is "KktlsDefaultSSLSocketFactory[<shown>: ...]". */
    private void assertDelegatesTo(String origin, String shown, SSLSocketFactory f) throws Exception {
        RecordingSSLSocketFactory.reset();
        Socket s = f.createSocket("example.org", 443);
        assertEquals(Arrays.asList(origin + ":createSocket(example.org,443)"), RecordingSSLSocketFactory.CALLS);
        assertSame(RecordingSSLSocketFactory.lastResult, s);
        s.close();
        assertTrue(f.toString(), f.toString().startsWith("KktlsDefaultSSLSocketFactory[" + shown + ": "));
    }

    private void assertOneFallbackRecord(Class<? extends Throwable> cause) {
        assertEquals("log records " + records, 1, records.size());
        LogRecord r = records.get(0);
        assertEquals(Level.WARNING, r.getLevel());
        assertEquals(LOG_TAG, r.getLoggerName());
        assertNotNull("the failure is attached", r.getThrown());
        assertTrue("thrown " + r.getThrown() + ", want " + cause.getName(), cause.isInstance(r.getThrown()));
        assertTrue(r.getMessage(), r.getMessage().contains("OpenSSLSocketFactoryImpl"));
    }

    private void assertFallsBack(String mode, Class<? extends Throwable> cause) throws Throwable {
        if (mode != null) {
            System.setProperty("kktlstest.mode", mode);
        }
        SSLSocketFactory f = newWrapper(loader("android", "conscrypt", "platform"));
        assertTrue(RecordingSSLSocketFactory.CALLS.toString(), RecordingSSLSocketFactory.CALLS.contains("platform:new"));
        assertDelegatesTo("platform", f);
        assertOneFallbackRecord(cause);
    }

    // --- Conscrypt usable

    public void testConscryptUsableDelegatesToItsTlsContext() throws Throwable {
        SSLSocketFactory f = newWrapper(loader("android", "conscrypt", "platform"));
        assertEquals("gate read, the wrapper's own loader for kktls-conscrypt.jar, the provider builder with TLSv1 not"
                + " deprecated and enabled, then SSLContext TLS of that provider, init with platform defaults, no"
                + " platform factory", CONSCRYPT_PATH, RecordingSSLSocketFactory.CALLS);
        assertDelegatesTo("conscrypt", f);
        assertEquals("no log line when Conscrypt is used", 0, records.size());
        assertNull("the Conscrypt provider is not installed in Security", Security.getProvider("StubConscrypt"));
    }

    public void testConscryptIsNotVisibleFromTheWrappersLoader() throws Throwable {
        RecordingLoader cl = loader("android", "conscrypt", "platform");
        assertTrue(newWrapper(cl).toString().contains("[conscrypt: "));
        try {
            Class.forName("org.conscrypt.Conscrypt", false, cl);
            fail("org.conscrypt.Conscrypt is visible from the wrapper's loader (the boot class path on the device)");
        } catch (ClassNotFoundException expected) {
            // only the wrapper's own PathClassLoader for kktls-conscrypt.jar sees it
        }
    }

    public void testLoaderAndProviderAreCreatedOncePerProcess() throws Throwable {
        RecordingLoader cl = loader("android", "conscrypt", "platform");
        for (int i = 0; i < 3; i++) {
            assertTrue(newWrapper(cl).toString().contains("[conscrypt: "));
        }
        List<String> calls = RecordingSSLSocketFactory.CALLS;
        assertEquals(calls.toString(), 1, count(calls, CONSCRYPT_LOADER));
        assertEquals(calls.toString(), 1, count(calls, BUILD));
        assertEquals(calls.toString(), 0, count(calls, NEW_PROVIDER));
        assertEquals("a fresh TLS context per construction: " + calls, 3, count(calls, INIT));
        assertNull(Security.getProvider("StubConscrypt"));
    }

    public void testConcurrentFirstConstructionCreatesOneLoader() throws Throwable {
        RecordingLoader cl = loader("android", "conscrypt", "platform");
        List<String> origins = constructConcurrently(cl, 8);
        for (String o : origins) {
            assertTrue(o, o.startsWith("KktlsDefaultSSLSocketFactory[conscrypt: "));
        }
        assertEquals(RecordingSSLSocketFactory.CALLS.toString(), 1, count(RecordingSSLSocketFactory.CALLS,
                CONSCRYPT_LOADER));
        assertEquals(1, count(RecordingSSLSocketFactory.CALLS, BUILD));
        assertEquals(0, records.size());
    }

    /** n threads construct the wrapper in cl at the same moment; returns their toString()s. */
    private static List<String> constructConcurrently(final ClassLoader cl, int n) throws Throwable {
        final CyclicBarrier start = new CyclicBarrier(n);
        final List<String> out = Collections.synchronizedList(new ArrayList<String>());
        final List<Throwable> errors = Collections.synchronizedList(new ArrayList<Throwable>());
        Class.forName(WRAPPER, true, cl); // class init (the gate read) first, as getDefault()'s Class.forName does
        List<Thread> threads = new ArrayList<Thread>();
        for (int i = 0; i < n; i++) {
            Thread t = new Thread() {
                @Override public void run() {
                    try {
                        start.await(10, TimeUnit.SECONDS);
                        out.add(newWrapper(cl).toString());
                    } catch (Throwable e) {
                        errors.add(e);
                    }
                }
            };
            threads.add(t);
            t.start();
        }
        for (Thread t : threads) {
            t.join(30000);
            assertFalse("construction thread hangs", t.isAlive());
        }
        if (!errors.isEmpty()) {
            throw errors.get(0);
        }
        assertEquals(n, out.size());
        return out;
    }

    /**
     * Conscrypt 2.6-alpha2's newProvider() takes the Android defaults (TLSv1 deprecated and not supported: TLS 1.2/1.3
     * only); the wrapper builds its provider with TLSv1 not deprecated and enabled, so TLS 1.0/1.1 servers and the 4.4
     * okhttp TLSv1 + SCSV retry keep working as with 2.5.3 and layer A (review of Tasks 10-12, finding 1).
     */
    public void testProviderIsBuiltWithTlsV1NotDeprecatedAndEnabled() throws Throwable {
        SSLSocketFactory f = newWrapper(loader("android", "conscrypt", "platform"));
        List<String> calls = RecordingSSLSocketFactory.CALLS;
        assertEquals(calls.toString(), 0, count(calls, NEW_PROVIDER));
        assertEquals(calls.toString(), PROVIDER_CALLS, calls.subList(2, 2 + PROVIDER_CALLS.size()));
        assertDelegatesTo("conscrypt", f);
        assertEquals(0, records.size());
    }

    // --- Conscrypt not usable: layer A (the platform factory), one log line

    /** A Conscrypt without the 2.6 TLSv1 switches (2.5.3 API shape): layer A, not a TLS 1.2/1.3-only provider. */
    public void testBuilderWithoutTlsV1SwitchesFallsBack() throws Throwable {
        SSLSocketFactory f = newWrapper(loader("android", "conscrypt253", "platform"));
        List<String> calls = RecordingSSLSocketFactory.CALLS;
        assertTrue(calls.toString(), calls.contains("platform:new"));
        assertFalse(calls.toString(), calls.contains(NEW_PROVIDER));
        assertFalse(calls.toString(), calls.contains("conscrypt:build"));
        assertDelegatesTo("platform", f);
        assertOneFallbackRecord(NoSuchMethodException.class);
    }


    public void testInstalledJarWithoutConscryptFallsBack() throws Throwable {
        SSLSocketFactory f = newWrapper(loader("android", "platform")); // installed, but the jar has no Conscrypt
        assertTrue(RecordingSSLSocketFactory.CALLS.toString(), RecordingSSLSocketFactory.CALLS.contains(CONSCRYPT_LOADER));
        assertDelegatesTo("platform", f);
        assertOneFallbackRecord(ClassNotFoundException.class);
    }

    public void testNoPathClassLoaderFallsBack() throws Throwable {
        SSLSocketFactory f = newWrapper(loader("android", "conscrypt", "platform", "nodalvik"));
        assertDelegatesTo("platform", f);
        assertOneFallbackRecord(ClassNotFoundException.class);
        for (String c : RecordingSSLSocketFactory.CALLS) {
            assertFalse("Conscrypt reached without a loader: " + c, c.startsWith("conscrypt:"));
        }
    }

    public void testUnsatisfiedLinkErrorFallsBack() throws Throwable {
        assertFallsBack("ule", UnsatisfiedLinkError.class);
    }

    public void testExceptionInInitializerErrorFallsBack() throws Throwable {
        assertFallsBack("eiie", ExceptionInInitializerError.class);
    }

    public void testRuntimeExceptionFallsBack() throws Throwable {
        assertFallsBack("rte", IllegalArgumentException.class);
    }

    public void testNoSuchAlgorithmExceptionFallsBack() throws Throwable {
        assertFallsBack("nsae", NoSuchAlgorithmException.class);
    }

    public void testKeyManagementExceptionFallsBack() throws Throwable {
        assertFallsBack("kme", KeyManagementException.class);
    }

    public void testNullSocketFactoryFallsBack() throws Throwable {
        assertFallsBack("null", IllegalStateException.class);
    }

    // --- libkktls_conscrypt_jni.so checked before the loader: a library the 4.4 linker would map past EOF (SIGBUS)
    //     is a fallback like any other, and the loader is never created, so nothing ever dlopens it

    /** The library in place, a fresh process: layer A, one log line whose IOException names the reason, no loader. */
    private void assertLibraryRefused(String what, byte[] content, String reason) throws Throwable {
        RecordingSSLSocketFactory.reset();
        records.clear();
        if (content == null) {
            assertTrue(LIBRARY.delete());
        } else {
            writeLibrary(content);
        }
        RecordingLoader cl = loader("android", "conscrypt", "platform");
        SSLSocketFactory f = newWrapper(cl);
        assertTrue(what + ": " + f, f.toString().startsWith("KktlsDefaultSSLSocketFactory[platform: "));
        for (String c : RecordingSSLSocketFactory.CALLS) {
            assertFalse(what + ": the loader was created, so the library would be opened: " + c, c.startsWith("dalvik:new"));
        }
        assertEquals(what + ": no org.conscrypt lookup", new ArrayList<String>(), cl.conscryptLookups());
        assertOneFallbackRecord(IOException.class);
        String m = records.get(0).getThrown().getMessage();
        assertTrue(what + ": " + m, m.contains(reason));
        assertDelegatesTo("platform", f);
    }

    private static byte[] with(byte[] b, int offset, int value) {
        byte[] c = b.clone();
        c[offset] = (byte) value;
        return c;
    }

    public void testLibraryCheckRefusesWhatTheLinkerWouldMapPastTheEnd() throws Throwable {
        byte[] ok = elf(EM_ARM, 8192);
        String elfCheck = "ELF check of " + LIBRARY.getPath() + ": ";
        assertLibraryRefused("truncated to 4096 bytes (the device repro)", Arrays.copyOf(ok, 4096),
                elfCheck + "PT_LOAD segment 2 ends at byte 8192, past the end of the file (4096 bytes): truncated");
        assertLibraryRefused("one byte short", Arrays.copyOf(ok, 8191), "segment 2 ends at byte 8192");
        byte[] huge = ok.clone();
        phdr(huge, 1, 1, 0xffffffffL, 0xffffffffL);
        assertLibraryRefused("p_offset + p_filesz over 32 bits (unsigned)", huge, "segment 1 ends at byte 8589934590");
        assertLibraryRefused("bad magic", with(ok, 1, 'X'), elfCheck + "no ELF magic");
        assertLibraryRefused("ELFCLASS64", with(ok, 4, 2), "not a 32-bit little-endian ELF (class 2, data 1)");
        assertLibraryRefused("big-endian", with(ok, 5, 2), "not a 32-bit little-endian ELF (class 1, data 2)");
        assertLibraryRefused("x86_64 machine", elf(62, 8192), "e_machine 62");
        assertLibraryRefused("ET_EXEC", with(ok, 16, 2), "e_type 2");
        assertLibraryRefused("empty (masked with /dev/null)", new byte[0], "shorter than an ELF header (0 bytes)");
        assertLibraryRefused("51 bytes", Arrays.copyOf(ok, 51), "shorter than an ELF header (51 bytes)");
        assertLibraryRefused("program headers past the end", Arrays.copyOf(ok, 100), "do not fit the file (100 bytes)");
        assertLibraryRefused("e_phentsize 40", with(ok, 42, 40), "3 x 40 bytes");
        assertLibraryRefused("no program header", with(ok, 44, 0), "0 x 32 bytes");
        byte[] noLoad = ok.clone();
        phdr(noLoad, 1, 0, 0, 4096); // PT_NULL
        phdr(noLoad, 2, 4, 4096, 4096); // PT_NOTE
        assertLibraryRefused("no PT_LOAD", noLoad, "no PT_LOAD segment");
        RecordingSSLSocketFactory.reset();
        records.clear();
        assertTrue(LIBRARY.delete());
        SSLSocketFactory f = newWrapper(loader("android", "conscrypt", "platform"));
        assertTrue(f.toString(), f.toString().startsWith("KktlsDefaultSSLSocketFactory[platform: "));
        assertFalse(RecordingSSLSocketFactory.CALLS.contains(CONSCRYPT_LOADER));
        assertOneFallbackRecord(FileNotFoundException.class);
    }

    public void testLibraryCheckAcceptsArmAndX86() throws Throwable {
        for (int machine : new int[] {EM_ARM, EM_386}) {
            RecordingSSLSocketFactory.reset();
            writeLibrary(elf(machine, 4097)); // the last segment is 1 byte, ending exactly at EOF
            SSLSocketFactory f = newWrapper(loader("android", "conscrypt", "platform"));
            assertEquals("e_machine " + machine, CONSCRYPT_PATH, RecordingSSLSocketFactory.CALLS);
            assertDelegatesTo("conscrypt", f);
        }
        assertEquals(0, records.size());
    }

    public void testTruncatedLibraryIsCheckedOncePerProcess() throws Throwable {
        writeLibrary(Arrays.copyOf(elf(EM_ARM, 8192), 4096));
        RecordingLoader cl = loader("android", "conscrypt", "platform");
        assertTrue(newWrapper(cl).toString().contains("[platform: "));
        install(); // repaired while the process runs: the failure is kept (no retry, no loader)
        assertTrue(newWrapper(cl).toString().contains("[platform: "));
        assertTrue(newWrapper(cl).toString().contains("[platform: "));
        assertEquals(0, count(RecordingSSLSocketFactory.CALLS, CONSCRYPT_LOADER));
        assertOneFallbackRecord(IOException.class);
        RecordingSSLSocketFactory.reset();
        assertTrue("a new process uses the repaired library", newWrapper(loader("android", "conscrypt", "platform"))
                .toString().contains("[conscrypt: "));
    }

    public void testLibraryIsNotReadWhenLayerDIsOffOrAbsent() throws Throwable {
        writeLibrary(new byte[0]); // would be refused (and logged) if the wrapper looked at it
        System.setProperty("kktlstest.gate", "0");
        assertGateOff(loader("android", "conscrypt", "platform"));
        System.setProperty("kktlstest.gate", "1");
        uninstall();
        RecordingSSLSocketFactory.reset();
        assertLayerA(loader("android", "conscrypt", "platform"), "absent", 1);
    }

    public void testFallbackLogsOncePerProcess() throws Throwable {
        System.setProperty("kktlstest.mode", "ule");
        ClassLoader cl = loader("android", "conscrypt", "platform");
        List<SSLSocketFactory> made = new ArrayList<SSLSocketFactory>();
        for (int i = 0; i < 3; i++) {
            made.add(newWrapper(cl));
        }
        assertEquals("the failure is kept for the process: no second loader " + RecordingSSLSocketFactory.CALLS, 1,
                count(RecordingSSLSocketFactory.CALLS, CONSCRYPT_LOADER));
        for (SSLSocketFactory f : made) {
            assertDelegatesTo("platform", f);
        }
        assertOneFallbackRecord(UnsatisfiedLinkError.class);
    }

    public void testConcurrentFirstConstructionLogsOnce() throws Throwable {
        System.setProperty("kktlstest.mode", "ule");
        RecordingLoader cl = loader("android", "conscrypt", "platform");
        for (String o : constructConcurrently(cl, 8)) {
            assertTrue(o, o.startsWith("KktlsDefaultSSLSocketFactory[platform: "));
        }
        assertOneFallbackRecord(UnsatisfiedLinkError.class);
        assertEquals(1, count(RecordingSSLSocketFactory.CALLS, CONSCRYPT_LOADER));
    }

    // --- nothing usable: a RuntimeException, so SSLSocketFactory.getDefault() (catch Exception) takes its own fallback

    public void testNoPlatformFactoryThrowsRuntimeException() throws Throwable {
        try {
            newWrapper(loader("android"));
            fail("expected IllegalStateException");
        } catch (IllegalStateException expected) {
            assertTrue(String.valueOf(expected.getCause()), expected.getCause() instanceof ClassNotFoundException);
            assertTrue(expected.getMessage(),
                    expected.getMessage().endsWith("is not usable (layer D installed, Conscrypt not usable either)"));
        }
    }

    public void testPlatformFactoryErrorThrowsRuntimeException() throws Throwable {
        System.setProperty("kktlstest.mode", "ule");
        System.setProperty("kktlstest.platform", "error");
        try {
            newWrapper(loader("android", "conscrypt", "platform"));
            fail("expected IllegalStateException");
        } catch (IllegalStateException expected) {
            assertTrue(String.valueOf(expected.getCause()), expected.getCause() instanceof LinkageError);
        }
    }

    // --- the kill switch persist.kktls.conscrypt: exactly "0" is off; off = layer A, no org.conscrypt lookup, no log;
    //     any other value (unset included) leaves the choice to the installed check

    /**
     * Layer A without trying Conscrypt (kill switch, or layer D not installed): the wrapper is the platform factory,
     * toString says {@code shown}, nothing was logged, the kill switch was read {@code gateReads} times (0 when the
     * android stub is absent), and no org.conscrypt class and no PathClassLoader was looked up. The Conscrypt stub on
     * the path throws from its static initializer ("eiie"), so any Class.forName of it would also have produced a
     * fallback log line.
     */
    private void assertLayerA(RecordingLoader cl, String shown, int gateReads) throws Throwable {
        System.setProperty("kktlstest.mode", "eiie");
        SSLSocketFactory f = newWrapper(cl);
        assertTrue(f.toString(), f.toString().startsWith("KktlsDefaultSSLSocketFactory[" + shown + ": "));
        assertEquals("no org.conscrypt lookup (" + shown + ")", new ArrayList<String>(), cl.conscryptLookups());
        assertFalse("no PathClassLoader for kktls-conscrypt.jar (" + shown + ")", cl.requested.contains(
                "dalvik.system.PathClassLoader"));
        assertEquals("no log line (" + shown + "): " + records, 0, records.size());
        assertTrue(RecordingSSLSocketFactory.CALLS.toString(), RecordingSSLSocketFactory.CALLS.contains("platform:new"));
        for (String c : RecordingSSLSocketFactory.CALLS) {
            assertFalse("Conscrypt used (" + shown + "): " + c, c.startsWith("conscrypt:"));
        }
        assertEquals(RecordingSSLSocketFactory.CALLS.toString(), gateReads,
                count(RecordingSSLSocketFactory.CALLS, GATE_READ));
        for (String c : RecordingSSLSocketFactory.CALLS) {
            assertFalse("a Conscrypt loader (" + shown + "): " + c, c.startsWith("dalvik:"));
        }
        assertDelegatesTo("platform", shown, f);
    }

    private void assertGateOff(RecordingLoader cl) throws Throwable {
        assertLayerA(cl, "gate-off", 1);
    }

    /** The full Conscrypt path, with {@code gateReads} reads of the kill switch before the loader. */
    private void assertConscrypt(RecordingLoader cl, int gateReads) throws Throwable {
        SSLSocketFactory f = newWrapper(cl);
        assertTrue(f.toString(), f.toString().startsWith("KktlsDefaultSSLSocketFactory[conscrypt: "));
        List<String> want = new ArrayList<String>(CONSCRYPT_PATH);
        if (gateReads == 0) {
            want.remove(GATE_READ);
        }
        assertEquals(want, RecordingSSLSocketFactory.CALLS);
        assertEquals("no log line: " + records, 0, records.size());
        assertDelegatesTo("conscrypt", f);
    }

    public void testGateUnsetUsesConscrypt() throws Throwable {
        System.clearProperty("kktlstest.gate");
        RecordingLoader cl = loader("android", "conscrypt", "platform");
        assertConscrypt(cl, 1);
        assertTrue("the kill switch is read through SystemProperties.get(key, \"\")", cl.requested.contains(
                "android.os.SystemProperties"));
    }

    public void testGateZeroIsOff() throws Throwable {
        System.setProperty("kktlstest.gate", "0");
        assertGateOff(loader("android", "conscrypt", "platform"));
    }

    public void testEveryOtherValueUsesConscrypt() throws Throwable {
        String[] values = {"", "1", "true", "false", "no", "off", "00", "0 ", " 0", "0\n", "-0", "0.0", "\u0660", "O"};
        for (String v : values) {
            System.setProperty("kktlstest.gate", v);
            RecordingSSLSocketFactory.reset();
            records.clear();
            try {
                assertConscrypt(loader("android", "conscrypt", "platform"), 1);
            } catch (Throwable t) {
                AssertionError e = new AssertionError("kill switch value \"" + v + "\": " + t);
                e.initCause(t);
                throw e;
            }
        }
    }

    public void testGateLookupFailureCountsAsUnset() throws Throwable {
        System.clearProperty("kktlstest.gate");
        assertConscrypt(loader("conscrypt", "platform"), 0); // no android.os.SystemProperties (host VM, no framework)
        for (String failure : new String[] {"!ule", "!rte", "!null"}) {
            System.setProperty("kktlstest.gate", failure);
            RecordingSSLSocketFactory.reset();
            records.clear();
            assertConscrypt(loader("android", "conscrypt", "platform"), 1);
        }
    }

    // --- layer D not installed (no kktls-conscrypt.jar): layer A, nothing looked up, nothing logged

    public void testNotInstalledIsLayerA() throws Throwable {
        uninstall();
        assertLayerA(loader("android", "conscrypt", "platform"), "absent", 1);
    }

    public void testNotInstalledWithoutFrameworkIsLayerA() throws Throwable {
        uninstall();
        System.clearProperty("kktlstest.gate");
        assertLayerA(loader("conscrypt", "platform"), "absent", 0); // host Dalvik: no SystemProperties, no jar
    }

    public void testKillSwitchWinsOverInstalled() throws Throwable {
        System.setProperty("kktlstest.gate", "0");
        assertGateOff(loader("android", "conscrypt", "platform")); // installed by setUp
        System.setProperty("kktlstest.gate", "0");
        uninstall();
        RecordingSSLSocketFactory.reset();
        assertGateOff(loader("android", "conscrypt", "platform")); // and the kill switch is checked first
    }

    public void testInstalledIsCheckedOncePerProcess() throws Throwable {
        uninstall();
        RecordingLoader absent = loader("android", "conscrypt", "platform");
        assertTrue(newWrapper(absent).toString().contains("[absent: "));
        install(); // the files appear while the process runs: it keeps "absent" (a reboot installs layer D)
        assertTrue(newWrapper(absent).toString().contains("[absent: "));
        assertEquals(new ArrayList<String>(), absent.conscryptLookups());

        RecordingSSLSocketFactory.reset();
        RecordingLoader present = loader("android", "conscrypt", "platform"); // a new process sees the jar
        assertTrue(newWrapper(present).toString().contains("[conscrypt: "));
        uninstall(); // removed while the process runs: the loaded provider stays in use
        assertTrue(newWrapper(present).toString().contains("[conscrypt: "));
        assertEquals(1, count(RecordingSSLSocketFactory.CALLS, CONSCRYPT_LOADER));
        assertEquals(0, records.size());
    }

    public void testNotInstalledWithoutPlatformFactoryThrowsRuntimeExceptionWithoutLog() throws Throwable {
        uninstall();
        RecordingLoader cl = loader("android", "conscrypt");
        try {
            newWrapper(cl);
            fail("expected IllegalStateException");
        } catch (IllegalStateException expected) {
            assertTrue(String.valueOf(expected.getCause()), expected.getCause() instanceof ClassNotFoundException);
            assertTrue(expected.getMessage(), expected.getMessage().endsWith("is not usable (layer D not installed)"));
        }
        assertEquals(new ArrayList<String>(), cl.conscryptLookups());
        assertEquals(0, records.size());
    }

    public void testGateOneUsesConscryptAndReadsTheGateOnce() throws Throwable {
        RecordingLoader cl = loader("android", "conscrypt", "platform");
        SSLSocketFactory f = newWrapper(cl);
        assertTrue(f.toString(), f.toString().startsWith("KktlsDefaultSSLSocketFactory[conscrypt: "));
        assertEquals(CONSCRYPT_PATH, RecordingSSLSocketFactory.CALLS);
        assertTrue(cl.conscryptLookups().toString(), cl.conscryptLookups().contains("org.conscrypt.Conscrypt"));
    }

    public void testGateIsReadOncePerProcess() throws Throwable {
        RecordingLoader on = loader("android", "conscrypt", "platform");
        for (int i = 0; i < 3; i++) {
            assertTrue(newWrapper(on).toString().contains("[conscrypt: "));
        }
        System.setProperty("kktlstest.gate", "0"); // a setprop after the first read: this process keeps its value
        assertTrue(newWrapper(on).toString().contains("[conscrypt: "));
        assertEquals(RecordingSSLSocketFactory.CALLS.toString(), 1, count(RecordingSSLSocketFactory.CALLS, GATE_READ));

        RecordingSSLSocketFactory.reset();
        RecordingLoader off = loader("android", "conscrypt", "platform"); // a new process sees "0"
        for (int i = 0; i < 3; i++) {
            assertTrue(newWrapper(off).toString().contains("[gate-off: "));
        }
        System.setProperty("kktlstest.gate", "1");
        assertTrue(newWrapper(off).toString().contains("[gate-off: "));
        assertEquals(RecordingSSLSocketFactory.CALLS.toString(), 1, count(RecordingSSLSocketFactory.CALLS, GATE_READ));
        assertEquals(new ArrayList<String>(), off.conscryptLookups());
        assertEquals(0, records.size());
    }

    public void testGateOffWithoutPlatformFactoryThrowsRuntimeExceptionWithoutLog() throws Throwable {
        System.setProperty("kktlstest.gate", "0");
        RecordingLoader cl = loader("android", "conscrypt");
        try {
            newWrapper(cl);
            fail("expected IllegalStateException");
        } catch (IllegalStateException expected) {
            assertTrue(String.valueOf(expected.getCause()), expected.getCause() instanceof ClassNotFoundException);
            // Conscrypt was never tried: the message must not say it was
            assertTrue(expected.getMessage(), expected.getMessage().endsWith("is not usable (gate off)"));
        }
        assertEquals(new ArrayList<String>(), cl.conscryptLookups());
        assertEquals(0, records.size());
    }

    // --- jsse.enableSNIExtension (review 1b): a value Conscrypt 2.5.3 rejects in every handshake -> layer A, one line

    private void assertOneSniRecord(String value) {
        assertEquals("log records " + records, 1, records.size());
        LogRecord r = records.get(0);
        assertEquals(Level.WARNING, r.getLevel());
        assertEquals(LOG_TAG, r.getLoggerName());
        assertNull("no exception: nothing failed, the value is refused up front", r.getThrown());
        assertTrue(r.getMessage(), r.getMessage().contains(SNI_PROPERTY + " is \"" + value + "\""));
        assertTrue(r.getMessage(), r.getMessage().contains("OpenSSLSocketFactoryImpl"));
    }

    public void testInvalidSniPropertyUsesThePlatformFactoryWithoutLoadingConscrypt() throws Throwable {
        String[] values = {"yes", "", "1", "0", "on", "true ", " false", "tru", "TRUE\n", "\u0131"};
        for (String v : values) {
            System.setProperty(SNI_PROPERTY, v);
            RecordingSSLSocketFactory.reset();
            records.clear();
            RecordingLoader cl = loader("android", "conscrypt", "platform");
            SSLSocketFactory f = newWrapper(cl);
            assertEquals("value \"" + v + "\": gate read, then the platform factory only",
                    Arrays.asList(GATE_READ, "platform:new"), RecordingSSLSocketFactory.CALLS);
            assertEquals("value \"" + v + "\": no org.conscrypt lookup", new ArrayList<String>(),
                    cl.conscryptLookups());
            assertFalse(cl.requested.contains("dalvik.system.PathClassLoader"));
            assertDelegatesTo("platform", "platform-sni", f);
            assertOneSniRecord(v);
        }
    }

    public void testValidSniValuesUseConscrypt() throws Throwable {
        String[] values = {null, "true", "false", "TRUE", "False", "tRuE"};
        for (String v : values) {
            if (v == null) {
                System.clearProperty(SNI_PROPERTY);
            } else {
                System.setProperty(SNI_PROPERTY, v);
            }
            RecordingSSLSocketFactory.reset();
            records.clear();
            SSLSocketFactory f = newWrapper(loader("android", "conscrypt", "platform"));
            assertEquals("value " + v, CONSCRYPT_PATH, RecordingSSLSocketFactory.CALLS);
            assertDelegatesTo("conscrypt", f);
            assertEquals("value " + v + ": no log line", 0, records.size());
        }
    }

    public void testInvalidSniPropertyLogsOncePerProcess() throws Throwable {
        System.setProperty(SNI_PROPERTY, "yes");
        RecordingLoader cl = loader("android", "conscrypt", "platform");
        for (int i = 0; i < 3; i++) {
            assertTrue(newWrapper(cl).toString().startsWith("KktlsDefaultSSLSocketFactory[platform-sni: "));
        }
        for (String o : constructConcurrently(cl, 8)) {
            assertTrue(o, o.startsWith("KktlsDefaultSSLSocketFactory[platform-sni: "));
        }
        assertOneSniRecord("yes");
        assertEquals(0, count(RecordingSSLSocketFactory.CALLS, CONSCRYPT_LOADER));
    }

    /**
     * The value is checked at each construction (the remaining window: a factory made while the value was valid keeps
     * Conscrypt, and Conscrypt then refuses its handshakes if the value is changed later; getDefault() makes one).
     */
    public void testSniValueIsCheckedAtEachConstruction() throws Throwable {
        RecordingLoader cl = loader("android", "conscrypt", "platform");
        System.setProperty(SNI_PROPERTY, "maybe");
        SSLSocketFactory first = newWrapper(cl);
        assertTrue(first.toString(), first.toString().startsWith("KktlsDefaultSSLSocketFactory[platform-sni: "));
        System.setProperty(SNI_PROPERTY, "true");
        SSLSocketFactory second = newWrapper(cl);
        assertTrue(second.toString(), second.toString().startsWith("KktlsDefaultSSLSocketFactory[conscrypt: "));
        System.setProperty(SNI_PROPERTY, "later");
        assertTrue("an existing factory keeps its delegate", second.toString().contains("[conscrypt: "));
        assertTrue(newWrapper(cl).toString().startsWith("KktlsDefaultSSLSocketFactory[platform-sni: "));
        assertOneSniRecord("maybe");
        assertEquals(1, count(RecordingSSLSocketFactory.CALLS, CONSCRYPT_LOADER));
    }

    public void testInvalidSniPropertyIsIgnoredWithTheGateOff() throws Throwable {
        System.setProperty("kktlstest.gate", "0");
        System.setProperty(SNI_PROPERTY, "yes");
        assertGateOff(loader("android", "conscrypt", "platform")); // layer A handles the value itself (0027); no line
    }

    public void testInvalidSniPropertyIsIgnoredWhenNotInstalled() throws Throwable {
        uninstall();
        System.setProperty(SNI_PROPERTY, "yes");
        assertLayerA(loader("android", "conscrypt", "platform"), "absent", 1);
    }

    public void testInvalidSniPropertyWithoutPlatformFactoryThrowsRuntimeException() throws Throwable {
        System.setProperty(SNI_PROPERTY, "yes");
        try {
            newWrapper(loader("android", "conscrypt"));
            fail("expected IllegalStateException");
        } catch (IllegalStateException expected) {
            assertTrue(String.valueOf(expected.getCause()), expected.getCause() instanceof ClassNotFoundException);
        }
    }

    // --- delegation of the whole 4.4 API

    private static String signature(Method m) {
        StringBuilder b = new StringBuilder(m.getName()).append('(');
        Class<?>[] p = m.getParameterTypes();
        for (int i = 0; i < p.length; i++) {
            b.append(i == 0 ? "" : ",").append(p[i].getName());
        }
        return b.append(')').toString();
    }

    public void testWrapperDeclaresEvery44Method() throws Throwable {
        Class<?> c = Class.forName(WRAPPER, false, loader("platform"));
        List<String> declared = new ArrayList<String>();
        for (Method m : c.getDeclaredMethods()) {
            if (Modifier.isPublic(m.getModifiers()) && !Modifier.isStatic(m.getModifiers())) {
                declared.add(signature(m));
            }
        }
        for (String api : API_44) {
            assertTrue(api + " is not overridden by the wrapper; declared: " + declared, declared.contains(api));
        }
        assertTrue("the wrapper class is final", Modifier.isFinal(c.getModifiers()));
    }

    private void assertEveryMethodDelegates(String origin, SSLSocketFactory f) throws Exception {
        InetAddress a = InetAddress.getByAddress("a.example", new byte[] {10, 0, 0, 1});
        InetAddress l = InetAddress.getByAddress("l.example", new byte[] {10, 0, 0, 2});
        Socket plain = new Socket();
        Object[][] cases = {
            {f.getDefaultCipherSuites(), "getDefaultCipherSuites()"},
            {f.getSupportedCipherSuites(), "getSupportedCipherSuites()"},
            {f.createSocket(), "createSocket()"},
            {f.createSocket(plain, "h.example", 8443, true), "createSocket(Socket,h.example,8443,true)"},
            {f.createSocket("h.example", 443), "createSocket(h.example,443)"},
            {f.createSocket("h.example", 444, l, 5000), "createSocket(h.example,444,10.0.0.2,5000)"},
            {f.createSocket(a, 445), "createSocket(10.0.0.1,445)"},
            {f.createSocket(a, 446, l, 5001), "createSocket(10.0.0.1,446,10.0.0.2,5001)"},
        };
        assertEquals(API_44.length, cases.length);
        List<String> want = new ArrayList<String>();
        for (Object[] c : cases) {
            want.add(origin + ":" + c[1]);
        }
        List<String> got = new ArrayList<String>(RecordingSSLSocketFactory.CALLS);
        got.remove(GATE_READ);
        got.remove(CONSCRYPT_LOADER);
        got.removeAll(PROVIDER_CALLS);
        got.remove(INIT);
        got.remove("platform:new");
        assertEquals(want, got);
        Object last = cases[cases.length - 1][0];
        assertSame("the delegate's result is returned unchanged", RecordingSSLSocketFactory.lastResult, last);
        assertEquals(origin + "-default", ((String[]) cases[0][0])[0]);
        assertEquals(origin + "-supported", ((String[]) cases[1][0])[0]);
        for (Object[] c : cases) {
            if (c[0] instanceof Socket) {
                ((Socket) c[0]).close();
            }
        }
        plain.close();
    }

    public void testEveryMethodDelegatesToConscrypt() throws Throwable {
        assertEveryMethodDelegates("conscrypt", newWrapper(loader("android", "conscrypt", "platform")));
    }

    public void testEveryMethodDelegatesToThePlatformFactory() throws Throwable {
        assertEveryMethodDelegates("platform", newWrapper(loader("android", "platform")));
    }

    public void testEveryMethodDelegatesToThePlatformFactoryWithTheGateOff() throws Throwable {
        System.setProperty("kktlstest.gate", "0");
        SSLSocketFactory f = newWrapper(loader("android", "conscrypt", "platform"));
        assertTrue(f.toString(), f.toString().contains("[gate-off: "));
        assertEveryMethodDelegates("platform", f);
    }

    public void testEveryMethodDelegatesToThePlatformFactoryWhenNotInstalled() throws Throwable {
        uninstall();
        SSLSocketFactory f = newWrapper(loader("android", "conscrypt", "platform"));
        assertTrue(f.toString(), f.toString().contains("[absent: "));
        assertEveryMethodDelegates("platform", f);
    }

    // --- the SSLv3 filter (org.conscrypt.KktlsFilteringSSLSocket, kktls-sslfilter.jar): a Conscrypt socket is wrapped so
    //     setEnabledProtocols keeps Conscrypt 2.5.3's "SSLv3" handling; a platform socket is not; a missing filter jar
    //     is the ordinary layer-A fallback. The wrap filter itself (filtering logic) is tested in KktlsFilteringSSLSocketTest.

    public void testConscryptSocketsAreWrappedInTheSslv3Filter() throws Throwable {
        SSLSocketFactory f = newWrapper(loader("android", "conscrypt", "platform"));
        assertTrue(f.toString(), f.toString().contains("[conscrypt: "));
        RecordingSSLSocketFactory.returnSslSocket = true;
        Socket s = f.createSocket("h.example", 443);
        try {
            assertEquals("a Conscrypt SSLSocket is wrapped in the SSLv3 filter", FILTER_SOCKET_CLASS,
                    s.getClass().getName());
        } finally {
            s.close();
        }
    }

    public void testLayeredConscryptSocketIsWrappedInTheSslv3Filter() throws Throwable {
        SSLSocketFactory f = newWrapper(loader("android", "conscrypt", "platform"));
        RecordingSSLSocketFactory.returnSslSocket = true;
        Socket plain = new Socket();
        Socket s = f.createSocket(plain, "h.example", 443, true);
        try {
            assertEquals("createSocket(Socket,String,int,boolean) is wrapped too", FILTER_SOCKET_CLASS,
                    s.getClass().getName());
        } finally {
            s.close();
            plain.close();
        }
    }

    public void testPlatformSocketsAreNotWrapped() throws Throwable {
        SSLSocketFactory f = newWrapper(loader("android", "platform"));
        assertTrue(f.toString(), f.toString().contains("[platform: "));
        RecordingSSLSocketFactory.returnSslSocket = true;
        Socket s = f.createSocket("h.example", 443);
        try {
            assertEquals("a platform socket is returned unwrapped", RecordingSSLSocket.class.getName(),
                    s.getClass().getName());
        } finally {
            s.close();
        }
    }

    public void testGateOffSocketsAreNotWrapped() throws Throwable {
        System.setProperty("kktlstest.gate", "0");
        SSLSocketFactory f = newWrapper(loader("android", "conscrypt", "platform"));
        assertTrue(f.toString(), f.toString().contains("[gate-off: "));
        RecordingSSLSocketFactory.returnSslSocket = true;
        Socket s = f.createSocket("h.example", 443);
        try {
            assertEquals("gate off: the socket is returned unwrapped", RecordingSSLSocket.class.getName(),
                    s.getClass().getName());
        } finally {
            s.close();
        }
    }

    public void testNotInstalledSocketsAreNotWrapped() throws Throwable {
        uninstall();
        SSLSocketFactory f = newWrapper(loader("android", "conscrypt", "platform"));
        assertTrue(f.toString(), f.toString().contains("[absent: "));
        RecordingSSLSocketFactory.returnSslSocket = true;
        Socket s = f.createSocket("h.example", 443);
        try {
            assertEquals("not installed: the socket is returned unwrapped", RecordingSSLSocket.class.getName(),
                    s.getClass().getName());
        } finally {
            s.close();
        }
    }

    public void testMissingFilterJarFallsBackToThePlatformFactory() throws Throwable {
        String saved = System.getProperty("kktlstest.filter");
        System.clearProperty("kktlstest.filter"); // kktls-sslfilter.jar not installed: the filter class cannot be loaded
        try {
            SSLSocketFactory f = newWrapper(loader("android", "conscrypt", "platform"));
            assertTrue(RecordingSSLSocketFactory.CALLS.toString(),
                    RecordingSSLSocketFactory.CALLS.contains("platform:new"));
            assertDelegatesTo("platform", f);
            assertOneFallbackRecord(ClassNotFoundException.class);
        } finally {
            if (saved == null) {
                System.clearProperty("kktlstest.filter");
            } else {
                System.setProperty("kktlstest.filter", saved);
            }
        }
    }

    // --- NEON check (ARM library only), before the Conscrypt loader exists: no NEON = SIGILL in the linker

    /** Layer A after a failed NEON check: platform factory, one log line with an IOException, no Conscrypt loader. */
    private void assertNoNeonFallback(RecordingLoader cl, String messagePart) throws Throwable {
        SSLSocketFactory f = newWrapper(cl);
        assertDelegatesTo("platform", f);
        assertOneFallbackRecord(IOException.class);
        String m = records.get(0).getThrown().getMessage();
        assertTrue(m, m.contains(messagePart));
        assertFalse("no PathClassLoader before the NEON check passed", cl.requested.contains(
                "dalvik.system.PathClassLoader"));
        assertEquals(new ArrayList<String>(), cl.conscryptLookups());
    }

    public void testArmWithoutNeonInAuxvFallsBack() throws Throwable {
        writeAuxv(HWCAP_WITHOUT_NEON);
        writeCpuinfo("swp half thumb fastmult vfp edsp neon vfpv3 tls"); // auxv decides; cpuinfo is not asked
        assertNoNeonFallback(loader("android", "conscrypt", "platform"), "AT_HWCAP 0x2fa0d7");
    }

    public void testNoNeonIsCheckedOncePerProcess() throws Throwable {
        writeAuxv(HWCAP_WITHOUT_NEON);
        RecordingLoader cl = loader("android", "conscrypt", "platform");
        assertNoNeonFallback(cl, "the CPU has no NEON");
        writeAuxv(HWCAP_WITH_NEON); // kept for the process, as any Conscrypt load failure
        assertTrue(newWrapper(cl).toString().contains("[platform: "));
        assertEquals("logged once: " + records, 1, records.size());
    }

    public void testArmWithNeonInAuxvUsesConscrypt() throws Throwable {
        writeCpuinfo("swp half thumb fastmult vfp edsp vfpv3 tls"); // auxv decides
        assertConscrypt(loader("android", "conscrypt", "platform"), 1);
    }

    public void testNoAuxvCpuinfoWithNeonUsesConscrypt() throws Throwable {
        deleteAuxv();
        writeCpuinfo("swp half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt");
        assertConscrypt(loader("android", "conscrypt", "platform"), 1);
    }

    public void testAuxvWithoutHwcapCpuinfoWithNeonUsesConscrypt() throws Throwable {
        writeAuxv(null);
        writeCpuinfo("half thumb fastmult vfp edsp neon vfpv3 tls");
        assertConscrypt(loader("android", "conscrypt", "platform"), 1);
    }

    public void testAuxvEntriesAfterAtNullAreIgnored() throws Throwable {
        byte[] v = new byte[32];
        le(v, 0, 6, 4); // AT_PAGESZ
        le(v, 4, 4096, 4);
        le(v, 16, 16, 4); // after AT_NULL (bytes 8-15): not part of the vector
        le(v, 20, HWCAP_WITH_NEON, 4);
        write(AUXV, v);
        assertNoNeonFallback(loader("android", "conscrypt", "platform"), "has no AT_HWCAP");
    }

    public void testNoAuxvCpuinfoWithoutNeonFallsBack() throws Throwable {
        deleteAuxv();
        writeCpuinfo("swp half thumb fastmult vfp edsp neonx vfpv3 tls"); // a word, not a substring
        assertNoNeonFallback(loader("android", "conscrypt", "platform"), "the CPU has no NEON");
    }

    public void testNeitherAuxvNorCpuinfoFallsBack() throws Throwable {
        deleteAuxv();
        writeCpuinfo(null);
        assertNoNeonFallback(loader("android", "conscrypt", "platform"), "cannot tell whether the CPU has NEON");
    }

    public void testCpuinfoWithoutFeaturesFallsBack() throws Throwable {
        deleteAuxv();
        write(CPUINFO, "Processor\t: ARMv7\nHardware\t: Goldfish\n".getBytes("ISO-8859-1"));
        assertNoNeonFallback(loader("android", "conscrypt", "platform"), "has no Features line");
    }

    public void testX86LibraryIsNotCheckedForNeon() throws Throwable {
        writeLibrary(elf(EM_386, 8192));
        writeAuxv(HWCAP_WITHOUT_NEON);
        assertConscrypt(loader("android", "conscrypt", "platform"), 1);
    }

    public void testNeonIsNotReadWhenLayerDIsOffOrAbsent() throws Throwable {
        writeAuxv(HWCAP_WITHOUT_NEON); // would be refused (and logged) if the wrapper looked at it
        System.setProperty("kktlstest.gate", "0");
        assertGateOff(loader("android", "conscrypt", "platform"));
        System.setProperty("kktlstest.gate", "1");
        uninstall();
        RecordingSSLSocketFactory.reset();
        assertLayerA(loader("android", "conscrypt", "platform"), "absent", 1);
    }

    // --- Android 4.1-4.3 (Jelly Bean libcore): platform factory and Conscrypt's KitKat adapter

    public void testJellyBeanPlatformFactoryWhenNotInstalled() throws Throwable {
        uninstall();
        SSLSocketFactory f = newWrapper(loader("android", "platformjb"));
        assertDelegatesTo("platform", "absent", f);
        assertTrue(f.toString(), f.toString().endsWith(": org.apache.harmony.xnet.provider.jsse.OpenSSLSocketFactoryImpl]"));
        assertEquals(0, records.size());
    }

    public void testJellyBeanPlatformFactoryOnFallback() throws Throwable {
        System.setProperty("kktlstest.mode", "ule");
        SSLSocketFactory f = newWrapper(loader("android", "conscrypt", "platformjb"));
        assertDelegatesTo("platform", f);
        assertTrue(f.toString(), f.toString().endsWith(": org.apache.harmony.xnet.provider.jsse.OpenSSLSocketFactoryImpl]"));
        assertOneFallbackRecord(UnsatisfiedLinkError.class);
    }

    public void test44PlatformFactoryWinsOverTheJellyBeanOne() throws Throwable {
        uninstall();
        SSLSocketFactory f = newWrapper(loader("android", "platform", "platformjb"));
        assertTrue(f.toString(), f.toString().endsWith(": com.android.org.conscrypt.OpenSSLSocketFactoryImpl]"));
    }

    public void testNoPlatformFactoryNamesTheJellyBeanClass() throws Throwable {
        uninstall();
        try {
            newWrapper(loader("android"));
            fail("no platform factory at all must throw");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage(), expected.getMessage().startsWith("the platform factory "
                    + "org.apache.harmony.xnet.provider.jsse.OpenSSLSocketFactoryImpl is not usable"));
        }
    }

    public void testJellyBeanTakesTheInnerFactoryOfTheKitKatAdapter() throws Throwable {
        System.setProperty("kktlstest.mode", "adapter");
        SSLSocketFactory f = newWrapper(loader("android", "conscrypt", "platformjb"));
        assertEquals(CONSCRYPT_PATH, RecordingSSLSocketFactory.CALLS);
        assertDelegatesTo("conscrypt", f); // exactly one call, to the inner factory: no "adapter:" call
        assertTrue(f.toString(), f.toString().endsWith(": org.conscrypt.OpenSSLSocketFactoryImpl]"));
        assertEquals(0, records.size());
        RecordingSSLSocketFactory.reset();
        RecordingSSLSocketFactory.returnSslSocket = true;
        Socket s = f.createSocket("example.org", 443);
        assertEquals("the inner factory's sockets get the SSLv3 filter too", FILTER_SOCKET_CLASS, s.getClass().getName());
        s.close();
    }

    public void test44KeepsTheKitKatAdapter() throws Throwable {
        System.setProperty("kktlstest.mode", "adapter");
        SSLSocketFactory f = newWrapper(loader("android", "conscrypt", "platform", "kitkat"));
        RecordingSSLSocketFactory.reset();
        f.createSocket("example.org", 443).close();
        assertEquals(Arrays.asList("adapter:createSocket", "conscrypt:createSocket(example.org,443)"),
                RecordingSSLSocketFactory.CALLS);
        assertTrue(f.toString(), f.toString().endsWith(": org.conscrypt.KitKatPlatformOpenSSLSocketAdapterFactory]"));
        assertEquals(0, records.size());
    }

    public void testJellyBeanAdapterWithoutInnerFactoryFallsBack() throws Throwable {
        System.setProperty("kktlstest.mode", "adapter-null");
        SSLSocketFactory f = newWrapper(loader("android", "conscrypt", "platformjb"));
        assertDelegatesTo("platform", f);
        assertOneFallbackRecord(IllegalStateException.class);
        assertTrue(records.get(0).getThrown().getMessage(), records.get(0).getThrown().getMessage().contains(
                "BaseOpenSSLSocketAdapterFactory.delegate is null"));
    }

    public void testJellyBeanPlainConscryptFactoryIsUsedAsItIs() throws Throwable {
        // not the adapter (as 2.6-alpha2 returns for SDK_INT >= 22): nothing to unwrap
        assertConscrypt(loader("android", "conscrypt", "platformjb"), 1);
    }

    // --- reflection only: no class reference to org.conscrypt in the wrapper's class files (javac 6 cannot read
    //     Conscrypt's major-51 classes, and the wrapper must link without kktls-conscrypt)

    public void testNoCompileTimeReferenceToOrgConscryptOrAndroid() throws Exception {
        File root = new File(dir("kktlstest.wrapper").toURI());
        List<File> classes = new ArrayList<File>();
        collect(root, classes);
        assertFalse("no class files under " + root, classes.isEmpty());
        for (File f : classes) {
            String s = new String(read(f), "ISO-8859-1");
            for (int i = s.indexOf("org/conscrypt/"); i >= 0; i = s.indexOf("org/conscrypt/", i + 1)) {
                assertTrue(f + " references org/conscrypt/ at byte " + i, i >= 12
                        && s.substring(i - 12, i).equals("com/android/"));
            }
            assertFalse(f + " references android/os/ (the kill switch must use reflection: libcore cannot link against the framework)",
                    s.contains("android/os/"));
            assertFalse(f + " references dalvik/system/ (the Conscrypt loader is created by reflection)",
                    s.contains("dalvik/system/"));
            assertTrue(f + " must name the class only as a string",
                    !f.getName().equals("KktlsDefaultSSLSocketFactory.class") || s.contains("org.conscrypt.Conscrypt"));
        }
    }

    private static void collect(File d, List<File> out) {
        File[] fs = d.listFiles();
        if (fs == null) {
            return;
        }
        for (File f : fs) {
            if (f.isDirectory()) {
                collect(f, out);
            } else if (f.getName().endsWith(".class")) {
                out.add(f);
            }
        }
    }

    private static byte[] read(File f) throws IOException {
        InputStream in = new FileInputStream(f);
        try {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            for (int n; (n = in.read(buf)) > 0; ) {
                b.write(buf, 0, n);
            }
            return b.toByteArray();
        } finally {
            in.close();
        }
    }
}
