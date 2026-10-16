/* Synthetic fixture for check_tls_lists.py --selftest. Not AOSP code. */
package org.conscrypt;

public class OpenSSLServerSocketImpl extends javax.net.ssl.SSLServerSocket {
    private String[] enabledProtocols = NativeCrypto.getDefaultProtocols();
    private String[] enabledCipherSuites = NativeCrypto.getDefaultCipherSuites();

    @Override
    public String[] getSupportedProtocols() {
        return NativeCrypto.getSupportedProtocols();
    }
}
