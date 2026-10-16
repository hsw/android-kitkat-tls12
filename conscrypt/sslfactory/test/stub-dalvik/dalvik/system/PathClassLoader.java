// SPDX-License-Identifier: Apache-2.0
/*
 * Host-test stub (Mac JDK only) of dalvik.system.PathClassLoader(String dexPath, String libraryPath, ClassLoader parent),
 * the loader the wrapper creates for /system/framework/kktls-conscrypt.jar + /system/framework/kktls-sslfilter.jar when the
 * gate is on (neither is on BOOTCLASSPATH). Every construction is recorded in RecordingSSLSocketFactory.CALLS as
 * "dalvik:new(<dexPath>,<libraryPath>,<parent's simple class name>)". The "jars" are class directories: the
 * stub-conscrypt one named by -Dkktlstest.jar (the test sets it when the case has Conscrypt installed) and, for the real
 * SSLv3-filtering wrapper socket (org.conscrypt.KktlsFilteringSSLSocket, kktls-sslfilter.jar), the one named by
 * -Dkktlstest.filter. Either unset = that jar is missing, so an org.conscrypt lookup for a class it would hold fails with
 * ClassNotFoundException, as on the device. The loader is parent-first like the real one.
 */
package dalvik.system;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;
import kktlstest.RecordingSSLSocketFactory;

public class PathClassLoader extends URLClassLoader {
    public PathClassLoader(String dexPath, String libraryPath, ClassLoader parent) {
        super(urls(), parent);
        RecordingSSLSocketFactory.CALLS.add("dalvik:new(" + dexPath + "," + libraryPath + ","
                + (parent == null ? "null" : parent.getClass().getSimpleName()) + ")");
    }

    private static URL[] urls() {
        List<URL> out = new ArrayList<URL>();
        add(out, System.getProperty("kktlstest.jar"));     // kktls-conscrypt.jar (stub Conscrypt)
        add(out, System.getProperty("kktlstest.filter"));  // kktls-sslfilter.jar (the real wrapper socket)
        return out.toArray(new URL[0]);
    }

    private static void add(List<URL> out, String dir) {
        if (dir == null) {
            return;
        }
        try {
            out.add(new File(dir).toURI().toURL());
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
