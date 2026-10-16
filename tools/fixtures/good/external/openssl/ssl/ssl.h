/* Synthetic fixture for check_tls_lists.py --selftest (the SSL_OP/SSL_MODE/SSL_VERIFY lines of OpenSSL 1.0.1u + the
   Android handshake_cutthrough patch at 0x200, as in Task 7c). */
#define SSL_OP_TLSEXT_PADDING 0x00000010L
#define SSL_OP_NO_TICKET 0x00004000L
#define SSL_OP_NO_SSLv3 0x02000000L
#define SSL_OP_NO_TLSv1 0x04000000L
#define SSL_OP_NO_TLSv1_2 0x08000000L
#define SSL_OP_NO_TLSv1_1 0x10000000L
#define SSL_MODE_RELEASE_BUFFERS 0x00000010L
#define SSL_MODE_SEND_CLIENTHELLO_TIME 0x00000020L
#define SSL_MODE_SEND_SERVERHELLO_TIME 0x00000040L
/* Send TLS_FALLBACK_SCSV in the ClientHello. */
#define SSL_MODE_SEND_FALLBACK_SCSV 0x00000080L
/* When set, clients may send application data before receipt of CCS and Finished. */
#define SSL_MODE_HANDSHAKE_CUTTHROUGH 0x00000200L
#define SSL_VERIFY_NONE 0x00
#define SSL_VERIFY_PEER 0x01
