#include "common.h"

#include <sys/socket.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <picotls/openssl.h>
#include <openssl/pem.h>
#include <errno.h>

ptls_context_t *get_tlsctx()
{
    static ptls_context_t tlsctx = {.random_bytes = ptls_openssl_random_bytes,
                                    .get_time = &ptls_get_time,
                                    .key_exchanges = ptls_openssl_key_exchanges,
                                    .cipher_suites = ptls_openssl_cipher_suites,
                                    .require_dhe_on_psk = 1};
    return &tlsctx;
}

struct addrinfo *get_address(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result;

    printf("resolving %s:%s\n", host, port);

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_family = AF_UNSPEC; // Let getaddrinfo decide if it's a hostname.
    hints.ai_socktype = SOCK_DGRAM;                 /* Datagram socket */
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
    hints.ai_protocol = IPPROTO_UDP;

    int s = getaddrinfo(host, port, &hints, &result);
    if(s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        return NULL;
    } else {
        return result;
    }
}

bool send_dgrams_default(int fd, struct sockaddr *dest, struct iovec *dgrams, size_t num_dgrams)
{
    for(size_t i = 0; i < num_dgrams; ++i) {
        struct msghdr mess = {
            .msg_name = dest,
            .msg_namelen = quicly_get_socklen(dest),
            .msg_iov = &dgrams[i], .msg_iovlen = 1
        };

        ssize_t bytes_sent;
        while ((bytes_sent = sendmsg(fd, &mess, 0)) == -1 && errno == EINTR);
        if (bytes_sent == -1) {
            perror("sendmsg failed");
            return false;
        }
    }

    return true;
}

#ifdef __linux__
    /* UDP GSO is only supported on linux */
    #ifndef UDP_SEGMENT
        #define UDP_SEGMENT 103 /* Set GSO segmentation size */
    #endif

bool send_dgrams_gso(int fd, struct sockaddr *dest, struct iovec *dgrams, size_t num_dgrams)
{
    struct iovec vec = {
        .iov_base = (void *)dgrams[0].iov_base,
        .iov_len = dgrams[num_dgrams - 1].iov_base + dgrams[num_dgrams - 1].iov_len - dgrams[0].iov_base
    };

    struct msghdr mess = {
        .msg_name = dest,
        .msg_namelen = quicly_get_socklen(dest),
        .msg_iov = &vec,
        .msg_iovlen = 1
    };

    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(uint16_t))];
    } cmsg;
    if (num_dgrams != 1) {
        cmsg.hdr.cmsg_level = SOL_UDP;
        cmsg.hdr.cmsg_type = UDP_SEGMENT;
        cmsg.hdr.cmsg_len = CMSG_LEN(sizeof(uint16_t));
        *(uint16_t *)CMSG_DATA(&cmsg.hdr) = dgrams[0].iov_len;
        mess.msg_control = &cmsg;
        mess.msg_controllen = (socklen_t)CMSG_SPACE(sizeof(uint16_t));
    }

    ssize_t bytes_sent;
    while ((bytes_sent = sendmsg(fd, &mess, 0)) == -1 && errno == EINTR);
    if (bytes_sent == -1) {
        perror("sendmsg failed");
        return false;
    }

    return true;
}

#endif

bool (*send_dgrams)(int fd, struct sockaddr *dest, struct iovec *dgrams, size_t num_dgrams) = send_dgrams_default;

void enable_gso()
{
    send_dgrams = send_dgrams_gso;
}

bool send_pending(quicly_context_t *ctx, int fd, quicly_conn_t *conn)
{
    #define SEND_BATCH_SIZE 16

    quicly_address_t dest, src;
    struct iovec dgrams[SEND_BATCH_SIZE];
    uint8_t dgrams_buf[PTLS_ELEMENTSOF(dgrams) * ctx->transport_params.max_udp_payload_size];
    size_t num_dgrams = SEND_BATCH_SIZE;
    size_t send_dgrams_c = 0;

    while(true) {
        num_dgrams = PTLS_ELEMENTSOF(dgrams);
        int quicly_res = quicly_send(conn, &dest, &src, dgrams, &num_dgrams, &dgrams_buf, sizeof(dgrams_buf));


        if(quicly_res != 0) {
            if(quicly_res != QUICLY_ERROR_FREE_CONNECTION) {
                printf("quicly_send failed with code %i\n", quicly_res);
            } else {
                printf("connection closed\n");
            }
            return false;
        } else if(num_dgrams == 0) {
            return true;
        }

        if (!send_dgrams(fd, &dest.sa, dgrams, num_dgrams)) {
            return false;
        }
    };
}

void print_escaped(const char *src, size_t len)
{
    for(size_t i = 0; i < len; ++i) {
        switch (src[i]) {
        case '\n':
            putchar('\\');
            putchar('n');
            break;
        case '\r':
            putchar('\\');
            putchar('r');
            break;
        default:
            putchar(src[i]);
        }
    }
    putchar('\n');
    fflush(stdout);
}

int resolve_address(struct sockaddr *sa, socklen_t *salen, const char *host, const char *port, int family, int type, int protocol)
{
    struct addrinfo *addr = get_address(host, port);
    if (addr == NULL) {
        return -1;
    }
    
    if (*salen < addr->ai_addrlen) {
        freeaddrinfo(addr);
        return -1;
    }
    
    memcpy(sa, addr->ai_addr, addr->ai_addrlen);
    *salen = addr->ai_addrlen;
    freeaddrinfo(addr);
    return 0;
}

void setup_session_cache(ptls_context_t *ctx)
{
    // Basic session cache setup - implementation depends on picotls setup
    // For now, just a placeholder - in real implementation this would
    // set up session ticket handling
}

void setup_log_event(ptls_context_t *ctx, const char *logfile)
{
    (void)ctx;
    (void)logfile;
}

void load_certificate_chain(ptls_context_t *ctx, const char *cert_file)
{
    if (ptls_load_certificates(ctx, cert_file) != 0) {
        fprintf(stderr, "failed to load certificate chain from %s\n", cert_file);
        exit(1);
    }
}

void load_private_key(ptls_context_t *ctx, const char *key_file)
{
    static ptls_openssl_sign_certificate_t sign_cert;
    static EVP_PKEY *private_key = NULL;

    if (private_key == NULL) {
        FILE *fp = fopen(key_file, "r");
        if (fp == NULL) {
            fprintf(stderr, "failed to open private key file %s\n", key_file);
            exit(1);
        }
        private_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
        if (private_key == NULL) {
            fprintf(stderr, "failed to read private key from %s\n", key_file);
            exit(1);
        }
    }

    if (ptls_openssl_init_sign_certificate(&sign_cert, private_key) != 0) {
        fprintf(stderr, "failed to initialize sign certificate from %s\n", key_file);
        exit(1);
    }
    ctx->sign_certificate = &sign_cert.super;
}

