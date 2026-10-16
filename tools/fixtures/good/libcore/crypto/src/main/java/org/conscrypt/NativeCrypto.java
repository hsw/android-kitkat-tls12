/*
 * Synthetic fixture for check_tls_lists.py --selftest (shape of libcore 4.4 NativeCrypto after the kktls
 * series). Not AOSP code.
 */
package org.conscrypt;

public final class NativeCrypto {
    private static final String SUPPORTED_PROTOCOL_SSLV3 = "SSLv3";
    private static final String SUPPORTED_PROTOCOL_TLSV1 = "TLSv1";
    private static final String SUPPORTED_PROTOCOL_TLSV1_1 = "TLSv1.1";
    private static final String SUPPORTED_PROTOCOL_TLSV1_2 = "TLSv1.2";

    public static final String TLS_EMPTY_RENEGOTIATION_INFO_SCSV
            = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
    public static final String TLS_FALLBACK_SCSV = "TLS_FALLBACK_SCSV";

    static {
        add("TLS_RSA_WITH_AES_128_CBC_SHA", "AES128-SHA");
        add("TLS_RSA_WITH_AES_256_CBC_SHA", "AES256-SHA");
        add("SSL_RSA_WITH_RC4_128_SHA", "RC4-SHA");
        add("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE-ECDSA-AES128-SHA");
        add("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE-ECDSA-AES256-SHA");
        add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE-RSA-AES128-SHA");
        add("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE-RSA-AES256-SHA");
        add("TLS_RSA_WITH_NULL_SHA256", "NULL-SHA256");
        add("TLS_RSA_WITH_AES_128_CBC_SHA256", "AES128-SHA256");
        add("TLS_RSA_WITH_AES_256_CBC_SHA256", "AES256-SHA256");
        add("TLS_RSA_WITH_AES_128_GCM_SHA256", "AES128-GCM-SHA256");
        add("TLS_RSA_WITH_AES_256_GCM_SHA384", "AES256-GCM-SHA384");
        add("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE-RSA-AES128-SHA256");
        add("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE-RSA-AES256-SHA256");
        add("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE-RSA-AES128-GCM-SHA256");
        add("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE-RSA-AES256-GCM-SHA384");
        add("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "DHE-DSS-AES128-SHA256");
        add("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", "DHE-DSS-AES256-SHA256");
        add("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", "DHE-DSS-AES128-GCM-SHA256");
        add("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", "DHE-DSS-AES256-GCM-SHA384");
        add("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", "ECDH-RSA-AES128-SHA256");
        add("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", "ECDH-RSA-AES256-SHA384");
        add("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", "ECDH-RSA-AES128-GCM-SHA256");
        add("TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", "ECDH-RSA-AES256-GCM-SHA384");
        add("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", "ECDH-ECDSA-AES128-SHA256");
        add("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", "ECDH-ECDSA-AES256-SHA384");
        add("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", "ECDH-ECDSA-AES128-GCM-SHA256");
        add("TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", "ECDH-ECDSA-AES256-GCM-SHA384");
        add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE-RSA-AES128-SHA256");
        add("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE-RSA-AES256-SHA384");
        add("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256");
        add("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE-RSA-AES256-GCM-SHA384");
        add("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE-ECDSA-AES128-SHA256");
        add("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE-ECDSA-AES256-SHA384");
        add("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256");
        add("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE-ECDSA-AES256-GCM-SHA384");
        add("TLS_DH_anon_WITH_AES_128_CBC_SHA256", "ADH-AES128-SHA256");
        add("TLS_DH_anon_WITH_AES_256_CBC_SHA256", "ADH-AES256-SHA256");
        add("TLS_DH_anon_WITH_AES_128_GCM_SHA256", "ADH-AES128-GCM-SHA256");
        add("TLS_DH_anon_WITH_AES_256_GCM_SHA384", "ADH-AES256-GCM-SHA384");
        // add("SSL_RSA_WITH_RC4_128_MD5", "RC4-MD5");  (a commented-out row is not a row)
    }

    private static final String[] SUPPORTED_CIPHER_SUITES;
    static {
        int size = STANDARD_TO_OPENSSL_CIPHER_SUITES.size();
        SUPPORTED_CIPHER_SUITES = new String[size + 2];
        SUPPORTED_CIPHER_SUITES[size] = TLS_EMPTY_RENEGOTIATION_INFO_SCSV;
        SUPPORTED_CIPHER_SUITES[size + 1] = TLS_FALLBACK_SCSV;
    }

    // SSL mode from ssl.h
    public static final long SSL_MODE_SEND_FALLBACK_SCSV   = 0x00000080L;
    public static final long SSL_MODE_HANDSHAKE_CUTTHROUGH = 0x00000200L;

    // SSL options from ssl.h
    public static final long SSL_OP_TLSEXT_PADDING = 0x00000010L;
    public static final long SSL_OP_NO_TICKET      = 0x00004000L;
    public static final long SSL_OP_NO_SSLv3       = 0x02000000L;
    public static final long SSL_OP_NO_TLSv1       = 0x04000000L;
    public static final long SSL_OP_NO_TLSv1_1     = 0x10000000L;
    public static final long SSL_OP_NO_TLSv1_2     = 0x08000000L;

    public static final int SSL_VERIFY_NONE = 0x00;
    public static final int SSL_VERIFY_PEER = 0x01;

    public static final byte TLS_CT_RSA_SIGN = 1;
    public static final byte TLS_CT_DSS_SIGN = 2;
    public static final byte TLS_CT_RSA_FIXED_DH = 3;
    public static final byte TLS_CT_DSS_FIXED_DH = 4;
    public static final byte TLS_CT_ECDSA_SIGN = 64;
    public static final byte TLS_CT_RSA_FIXED_ECDH = 65;
    public static final byte TLS_CT_ECDSA_FIXED_ECDH = 66;

    public static native long[] SSL_get_ciphers(long ssl);

    public static final int SSL_kRSA = 0x00000001;
    public static final int SSL_kDHr = 0x00000002;
    public static final int SSL_kDHd = 0x00000004;
    public static final int SSL_kEDH = 0x00000008;
    public static final int SSL_kKRB5 = 0x00000010;
    public static final int SSL_kECDHr = 0x00000020;
    public static final int SSL_kECDHe = 0x00000040;
    public static final int SSL_kEECDH = 0x00000080;
    public static final int SSL_kPSK = 0x00000100;
    public static final int SSL_kGOST = 0x00000200;
    public static final int SSL_kSRP = 0x00000400;
    public static final int SSL_aRSA = 0x00000001;
    public static final int SSL_aDSS = 0x00000002;
    public static final int SSL_aNULL = 0x00000004;
    public static final int SSL_aDH = 0x00000008;
    public static final int SSL_aECDH = 0x00000010;
    public static final int SSL_aKRB5 = 0x00000020;
    public static final int SSL_aECDSA = 0x00000040;
    public static final int SSL_aPSK = 0x00000080;
    public static final int SSL_aGOST94 = 0x00000100;
    public static final int SSL_aGOST01 = 0x00000200;

    private static final String[] TLSV12_PROTOCOLS = new String[] {
        SUPPORTED_PROTOCOL_TLSV1,
        SUPPORTED_PROTOCOL_TLSV1_1,
        SUPPORTED_PROTOCOL_TLSV1_2,
    };

    public static String[] getDefaultCipherSuites() {
        return new String[] {
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        };
    }

    public static String[] getDefaultProtocols() {
        return TLSV12_PROTOCOLS.clone();
    }

    public static String[] getSupportedProtocols() {
        return new String[] { SUPPORTED_PROTOCOL_SSLV3,
                              SUPPORTED_PROTOCOL_TLSV1,
                              SUPPORTED_PROTOCOL_TLSV1_1,
                              SUPPORTED_PROTOCOL_TLSV1_2,
        };
    }

    public static String[] checkEnabledCipherSuites(String[] cipherSuites) {
        for (String cipherSuite : cipherSuites) {
            if (cipherSuite.equals(TLS_EMPTY_RENEGOTIATION_INFO_SCSV) ||
                    cipherSuite.equals(TLS_FALLBACK_SCSV)) {
                continue;
            }
        }
        return cipherSuites;
    }

    public static void setEnabledCipherSuites(long ssl, String[] cipherSuites) {
        for (String cipherSuite : cipherSuites) {
            if (cipherSuite.equals(TLS_FALLBACK_SCSV)) {
                SSL_set_mode(ssl, SSL_MODE_SEND_FALLBACK_SCSV);
                continue;
            }
        }
    }
}
