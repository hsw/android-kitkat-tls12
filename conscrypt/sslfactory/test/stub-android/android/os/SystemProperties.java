// SPDX-License-Identifier: Apache-2.0
/*
 * Host-test stub (Mac JDK only) of the hidden Android class android.os.SystemProperties: only get(String, String), the
 * method the wrapper's gate reads persist.kktls.conscrypt with (Task 11b). Every call is recorded in
 * RecordingSSLSocketFactory.CALLS as "props:get(<key>,<def>)", so a test can count the reads per process (class loader).
 * The value comes from -Dkktlstest.gate:
 *   unset             the property is unset: returns def, as the 4.4 native_get(key, def) does for an empty value
 *   "<v>"             returns v (also "", which 4.4 never returns for a non-null def, to prove "" is off anyway)
 *   "!ule"            get() throws UnsatisfiedLinkError (no framework natives registered, e.g. a bare dalvikvm)
 *   "!rte"            get() throws IllegalArgumentException (any RuntimeException)
 *   "!null"           get() returns null
 */
package android.os;

import kktlstest.RecordingSSLSocketFactory;

public final class SystemProperties {
    private SystemProperties() {}

    public static String get(String key, String def) {
        RecordingSSLSocketFactory.CALLS.add("props:get(" + key + "," + def + ")");
        String v = System.getProperty("kktlstest.gate");
        if (v == null) {
            return def;
        }
        if ("!ule".equals(v)) {
            throw new UnsatisfiedLinkError("stub: native_get not registered");
        }
        if ("!rte".equals(v)) {
            throw new IllegalArgumentException("stub: SystemProperties.get fails");
        }
        if ("!null".equals(v)) {
            return null;
        }
        return v;
    }
}
