package libcore.net.http;

// check_tls_lists.py fixture (Jelly Bean, group libcore.net.http): the shape of the TLS-intolerance retry of
// setupSecureSocket after the fix, TLSv1 plus TLS_FALLBACK_SCSV when the socket supports it (4.4 okhttp's
// Platform.supportTlsIntolerantServer). Not the real class.
final class HttpConnection {
    public void setupSecureSocket(SSLSocketFactory sslSocketFactory, boolean tlsTolerant)
            throws IOException {
        unverifiedSocket = (SSLSocket) sslSocketFactory.createSocket(socket,
                address.uriHost, address.uriPort, true /* autoClose */);
        if (tlsTolerant && unverifiedSocket instanceof OpenSSLSocketImpl) {
            OpenSSLSocketImpl openSslSocket = (OpenSSLSocketImpl) unverifiedSocket;
            openSslSocket.setUseSessionTickets(true);
            openSslSocket.setHostname(address.uriHost);
        } else {
            supportTlsIntolerantServer(unverifiedSocket);
        }
        unverifiedSocket.startHandshake();
    }

    private static void supportTlsIntolerantServer(SSLSocket socket) {
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
