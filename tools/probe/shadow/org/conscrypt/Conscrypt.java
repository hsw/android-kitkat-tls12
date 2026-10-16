// SPDX-License-Identifier: Apache-2.0
package org.conscrypt;

/**
 * Stub of an app-bundled Conscrypt for the Task 11 shadow check (tls-probe.sh shadow): built into the probe jar, so the
 * probe's class loader holds an org.conscrypt.Conscrypt of its own. kktls-conscrypt.jar is not on the boot class path (the
 * wrapper loads it with its own class loader, gate on only), so parent-first delegation finds no boot copy and this
 * class must be the one returned in both gate states; the marker field tells which copy a lookup returned. (Before the
 * review fix, with kktls-conscrypt.jar on the boot class path, the boot copy won and this class was never loaded.)
 */
public final class Conscrypt {
    public static final String KKTLS_APP_COPY = "probe-bundled stub";

    private Conscrypt() {
    }

    public static String version() {
        return "app-copy-stub";
    }
}
