/* Synthetic fixture for check_tls_lists.py --selftest. Not AOSP code. */
package com.squareup.okhttp.internal;

import javax.net.ssl.SSLSocket;

public final class Platform {
    public void supportTlsIntolerantServer(SSLSocket socket) {
        // Fallback: TLSv1 with TLS_FALLBACK_SCSV (not "SSLv3" any more)
        final String fallbackScsv = "TLS_FALLBACK_SCSV";
        boolean socketSupportsFallbackScsv = false;
        String[] supportedCipherSuites = socket.getSupportedCipherSuites();
        for (int i = supportedCipherSuites.length - 1; i >= 0; i--) {
            if (fallbackScsv.equals(supportedCipherSuites[i])) {
                socketSupportsFallbackScsv = true;
                break;
            }
        }
        if (socketSupportsFallbackScsv) {
            String[] enabledCipherSuites = socket.getEnabledCipherSuites();
            String[] newEnabledCipherSuites = new String[enabledCipherSuites.length + 1];
            System.arraycopy(enabledCipherSuites, 0, newEnabledCipherSuites, 0, enabledCipherSuites.length);
            newEnabledCipherSuites[newEnabledCipherSuites.length - 1] = fallbackScsv;
            socket.setEnabledCipherSuites(newEnabledCipherSuites);
        }
        socket.setEnabledProtocols(new String[]{"TLSv1"});
    }
}
