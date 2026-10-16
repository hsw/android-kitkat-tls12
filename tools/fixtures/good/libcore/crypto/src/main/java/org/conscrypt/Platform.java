/* Synthetic fixture for check_tls_lists.py --selftest (A8 literal IP test without DNS). Not AOSP code. */
package org.conscrypt;

import java.net.InetAddress;

class Platform {
    public static boolean isLiteralIpAddress(String hostname) {
        return InetAddress.isNumeric(hostname);
    }
}
