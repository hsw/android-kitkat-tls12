/* Synthetic fixture for check_tls_lists.py --selftest (server key types after the kktls port of 2d089e18; SNI host of A8).
   Not AOSP code. */
package org.conscrypt;

import java.net.InetAddress;

public class OpenSSLSocketImpl extends javax.net.ssl.SSLSocket {
    private String hostname;
    private Boolean useSni;
    private String peerHostname;
    private String wrappedHost;

    protected OpenSSLSocketImpl(String host, int port) throws Exception {
        super(host, port);
        this.peerHostname = host;
    }

    protected OpenSSLSocketImpl(String host, int port,
                                InetAddress clientAddress, int clientPort) throws Exception {
        super(host, port, clientAddress, clientPort);
        this.peerHostname = host;
    }

    protected OpenSSLSocketImpl(InetAddress address, int port) throws Exception {
        super(address, port);
    }

    private void startHandshake(long sslNativePointer, boolean client) throws Exception {
        String sniHostname = getSniHostname();
        if (AddressUtils.isValidSniHostname(sniHostname)) {
            NativeCrypto.SSL_set_tlsext_host_name(sslNativePointer, sniHostname);
        }
        if (!client) {
            for (long sslCipherNativePointer : NativeCrypto.SSL_get_ciphers(sslNativePointer)) {
                String keyType = getServerKeyType(sslCipherNativePointer);
            }
        }
    }

    private static String getServerKeyType(long sslCipherNative) throws Exception {
        int algorithm_mkey = NativeCrypto.get_SSL_CIPHER_algorithm_mkey(sslCipherNative);
        return algorithm_mkey == NativeCrypto.SSL_kRSA ? "RSA" : null;
    }

    private String getSniHostname() {
        if (useSni != null) {
            return useSni.booleanValue() ? hostname : null;
        }
        if (!isSniEnabledByDefault()) {
            return null;
        }
        return (peerHostname != null) ? peerHostname : wrappedHost;
    }

    private static boolean isSniEnabledByDefault() {
        String enableSNI = System.getProperty("jsse.enableSNIExtension", "true");
        return "true".equalsIgnoreCase(enableSNI);
    }

    String getPeerHostName() {
        if (wrappedHost != null) {
            return wrappedHost;
        }
        InetAddress inetAddress = super.getInetAddress();
        return (inetAddress != null) ? inetAddress.getHostName() : null;
    }

    public void setHostname(String hostname) {
        useSni = Boolean.valueOf(hostname != null);
        this.hostname = hostname;
    }
}
