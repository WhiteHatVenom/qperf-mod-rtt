#pragma once

#include <quicly.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>

ptls_context_t *get_tlsctx();

struct addrinfo *get_address(const char *host, const char *port);
int resolve_address(struct sockaddr *sa, socklen_t *salen, const char *host, const char *port, int family, int type, int protocol);
void setup_session_cache(ptls_context_t *ctx);
void setup_log_event(ptls_context_t *ctx, const char *logfile);
void load_certificate_chain(ptls_context_t *ctx, const char *cert_file);
void load_private_key(ptls_context_t *ctx, const char *key_file);
void enable_gso();
bool send_pending(quicly_context_t *ctx, int fd, quicly_conn_t *conn);
void print_escaped(const char *src, size_t len);


static inline int64_t min_int64(int64_t a, int64_t b)
{
    if(a < b) {
        return a;
    } else {
        return b;
    }
}

static inline int64_t max_int64(int64_t a, int64_t b) {
    if(a > b) {
        return a;
    } else {
        return b;
    }
}

static inline int64_t clamp_int64(int64_t val, int64_t min, int64_t max)
{
    if(val < min) {
        return min;
    }
    if(val > max) {
        return max;
    }
    return val;
}

static inline uint64_t get_current_pid()
{
    uint64_t pid;

    #ifdef __APPLE__
        pthread_threadid_np(NULL, &pid);
    #else
        pid = syscall(SYS_gettid);
    #endif

    return pid;
}