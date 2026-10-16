/* Synthetic fixture for check_tls_lists.py --selftest (A8 SNI host validation). Not AOSP code. */
package org.conscrypt;

public final class AddressUtils {
    public static boolean isValidSniHostname(String sniHostname) {
        if (sniHostname == null) {
            return false;
        }
        if (sniHostname.indexOf('.') == -1) {
            return false;
        }
        return !Platform.isLiteralIpAddress(sniHostname);
    }
}
