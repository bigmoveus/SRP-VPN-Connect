//
//  SRPSSHBridge.c
//  SRPCore
//
//  See SRPSSHBridge.h. Single pump thread owns the libssh2 session and all
//  channels; the packet engine runs on its own thread; the two are joined
//  by a socketpair per flow (installed through the engine's stream hook).
//

#include "SRPSSHBridge.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>
#ifdef __APPLE__
#include <mach/mach.h>
#endif

#include <libssh2.h>

/* libssh2's own packet reader (vendored 1.11.1): with no channel asking for data it is the only way to answer the
 * server's keepalives and to see its disconnect while the session is idle */
extern int _libssh2_transport_read(LIBSSH2_SESSION *session);

/* Engine entry points and the stream hook — all renamed to srpssh_* by the
 * prefix header (see SSH/build_engine.sh). */
#include "srpssh-prefix.h"
#include "hev-main.h"
#include "srp-ssh-hook.h"

#pragma mark - stream state

enum {
    ST_GREET = 0,   // reading the engine's SOCKS greeting
    ST_REQ,         // reading the engine's SOCKS request
    ST_OPEN,        // opening the SSH channel (each open waits on its own; see libssh2_channel_direct_tcpip_start)
    ST_HEV,         // HEV auth + FWD UDP handshake on the channel
    ST_SPLICE,      // pumping data both ways
    ST_DEAD
};

typedef struct SStream {
    int efd;                    // engine side of the socketpair (we keep this end)
    LIBSSH2_CHANNEL *ch;
    int state;
    int is_udp;
    int ch_eof_sent;
    int eng_eof_sent;           // shutdown(efd, SHUT_WR) done

    uint8_t hbuf[300];          // socks greeting/request accumulator
    size_t hlen, hneed;

    char dest_host[256];
    int dest_port;

    int hev_step;               // 0..5 handshake progress
    uint8_t hev_w[600];         // pending handshake bytes for the channel
    size_t hev_wlen, hev_woff;

    uint8_t wbuf[32768];        // engine -> channel pending
    size_t wlen;
    uint8_t rbuf[65536];        // channel -> engine pending
    size_t rlen, roff;
    struct timespec born;       // stream creation time
    unsigned long long down, up;   // bytes from the server to the engine, and back

    struct SStream *next;
} SStream;

#pragma mark - globals (single session)

static LIBSSH2_SESSION *g_sess;
static int g_sock = -1;
static pthread_t g_pump_thread;
static pthread_t g_engine_thread;
static int g_wake[2] = {-1, -1};
static volatile int g_quit;
static volatile int g_ready;
static volatile int g_failed;

static SStream *g_streams;
static pthread_mutex_t g_streams_mu = PTHREAD_MUTEX_INITIALIZER;

/* channels whose close is still waiting for room on the session socket; freed as soon as it went (each could hold up
 * to its window of the server's data meanwhile) */
static LIBSSH2_CHANNEL *g_closing[256];
static int g_closing_count;

static void free_channel(LIBSSH2_CHANNEL *ch) {
    libssh2_channel_close(ch);
    if (libssh2_channel_free(ch) == LIBSSH2_ERROR_EAGAIN && g_closing_count < 256) g_closing[g_closing_count++] = ch;
}

static void retry_closing(void) {
    int kept = 0;
    for (int i = 0; i < g_closing_count; i++) {
        libssh2_channel_close(g_closing[i]);
        if (libssh2_channel_free(g_closing[i]) == LIBSSH2_ERROR_EAGAIN) g_closing[kept++] = g_closing[i];
    }
    g_closing_count = kept;
}

/* throughput counters (bytes moved by the bridge) */
static unsigned long long g_bytes_up, g_bytes_down;
static struct timespec g_last_stat;

/* hook handoff: engine thread -> pump thread */
static int g_pending_fds[64];
static int g_pending_count;
static pthread_mutex_t g_pending_mu = PTHREAD_MUTEX_INITIALIZER;

static SRPSSHBridgeConfig g_cfg;
static SRPSSHLogCallback g_log;
static void *g_log_ctx;
static SRPSSHReadyCallback g_ready_cb;
static SRPSSHFailCallback g_fail_cb;
static SRPSSHGoneCallback g_gone_cb;
static void *g_cb_ctx;

static char g_engine_conf[512];

/* session liveness: when the socket last gave data, and how it ended */
static volatile time_t g_last_rx;
static volatile int g_rx_eof;           // the server closed the TCP connection
static volatile int g_rx_errno;         // the last receive error
static time_t g_deadline;               // connect, login and checks must finish by then
static char g_detail[256];              // the failure detail handed to the fail callback
static int g_flows_opened;              // channels opened for flows in this session

#pragma mark - logging

static void blog(int level, const char *fmt, ...);
static void libssh2_global_init(void);

/// level: 0 normal (milestones, errors), 1 expert, 2 debug
static void blog(int level, const char *fmt, ...) {
    if (!g_log || level > g_cfg.log_level) return;
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    g_log(g_log_ctx, level, line);
}

#pragma mark - small helpers

static int set_nb(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static time_t now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

/// The process's memory as the system counts it against the extension limit (0 where unknown)
static double footprint_mib(void) {
#ifdef __APPLE__
    task_vm_info_data_t info;
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count) == KERN_SUCCESS)
        return (double)info.phys_footprint / (1024.0 * 1024.0);
#endif
    return 0;
}

/// libssh2's receive, recording when data came and how the connection ended
static ssize_t srp_recv(libssh2_socket_t sock, void *buffer, size_t length, int flags, void **abstract) {
    (void)abstract;
    ssize_t n = recv(sock, buffer, length, flags);
    if (n > 0) { g_last_rx = now_sec(); return n; }
    if (n == 0) { g_rx_eof = 1; return 0; }
    int err = errno;
    if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR) return -EAGAIN;
    g_rx_errno = err;
    return -err;
}

/* What libssh2 sent that the socket has not taken yet. libssh2 copes badly with a send cut short: every other sender then
 * gets EAGAIN until the first one sends again with the same buffer, which its keepalive (retried only after the next
 * interval) and channel EOF never do, so the whole session stalled under load. Here libssh2's sends always go whole, and
 * the pump hands the rest to the socket in order; channel writes wait while too much is queued. */
static uint8_t *g_txq;
static size_t g_txq_len, g_txq_off, g_txq_cap;
enum { TXQ_PAUSE = 1024 * 1024 };

static size_t txq_pending(void) { return g_txq_len - g_txq_off; }

/// Sends what is queued; -1 when the connection broke (errno kept in g_rx_errno for the reason).
static int txq_flush(int sock) {
    while (g_txq_off < g_txq_len) {
#ifdef MSG_NOSIGNAL
        ssize_t n = send(sock, g_txq + g_txq_off, g_txq_len - g_txq_off, MSG_NOSIGNAL);
#else
        ssize_t n = send(sock, g_txq + g_txq_off, g_txq_len - g_txq_off, 0);
#endif
        if (n > 0) { g_txq_off += (size_t)n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
        g_rx_errno = n < 0 ? errno : EPIPE;
        return -1;
    }
    g_txq_off = g_txq_len = 0;
    return 0;
}

/// libssh2's send: all of it goes, now or through the queue
static ssize_t srp_send(libssh2_socket_t sock, const void *buffer, size_t length, int flags, void **abstract) {
    (void)abstract;
    if (txq_flush(sock) < 0) return -g_rx_errno;
    size_t done = 0;
    if (txq_pending() == 0) {
        ssize_t n = send(sock, buffer, length, flags);
        if (n < 0) {
            int err = errno;
            if (err != EAGAIN && err != EWOULDBLOCK && err != EINTR) { g_rx_errno = err; return -err; }
            n = 0;
        }
        done = (size_t)n;
    }
    if (done < length) {
        size_t rest = length - done;
        if (g_txq_off > 0) {
            memmove(g_txq, g_txq + g_txq_off, txq_pending());
            g_txq_len -= g_txq_off;
            g_txq_off = 0;
        }
        if (g_txq_len + rest > g_txq_cap) {
            size_t cap = g_txq_cap ? g_txq_cap : 65536;
            while (cap < g_txq_len + rest) cap *= 2;
            uint8_t *bigger = realloc(g_txq, cap);
            if (!bigger) return -ENOMEM;
            g_txq = bigger;
            g_txq_cap = cap;
        }
        memcpy(g_txq + g_txq_len, (const uint8_t *)buffer + done, rest);
        g_txq_len += rest;
    }
    return (ssize_t)length;
}

static void wake_pump(void) {
    if (g_wake[1] >= 0) (void)write(g_wake[1], "w", 1);
}

#pragma mark - engine stream hook (runs on engine task threads)

static int srpssh_hook_open(void) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
        return -1;
    set_nb(fds[0]);
    set_nb(fds[1]);
    int sz = 256 * 1024;
    setsockopt(fds[0], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
    setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));

    pthread_mutex_lock(&g_pending_mu);
    if (g_pending_count < 64) {
        g_pending_fds[g_pending_count++] = fds[0];
    } else {
        pthread_mutex_unlock(&g_pending_mu);
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    pthread_mutex_unlock(&g_pending_mu);
    wake_pump();
    blog(2, "SSH: new flow: bridge fd %d, engine fd %d", fds[0], fds[1]);
    return fds[1];   // engine end
}

#pragma mark - per-stream helpers

static SStream *stream_new(int efd) {
    SStream *st = calloc(1, sizeof(SStream));
    if (!st) return NULL;
    st->efd = efd;
    st->state = ST_GREET;
    st->hneed = 2;
    clock_gettime(CLOCK_MONOTONIC, &st->born);
    pthread_mutex_lock(&g_streams_mu);
    st->next = g_streams;
    g_streams = st;
    pthread_mutex_unlock(&g_streams_mu);
    return st;
}

static void stream_free(SStream *st) {
    blog(2, "SSH: flow fd %d to %s:%d ends (state %d, eof to server %d, eof to engine %d, down %llu, up %llu)",
         st->efd, st->dest_host, st->dest_port, st->state, st->ch_eof_sent, st->eng_eof_sent, st->down, st->up);
    if (st->efd >= 0) close(st->efd);
    if (st->ch) free_channel(st->ch);
    free(st);
}

/// Queue bytes for the engine side; flushed with POLLOUT.
static int queue_to_engine(SStream *st, const void *data, size_t len) {
    if (len > sizeof(st->rbuf) - st->rlen) return -1;
    memcpy(st->rbuf + st->rlen, data, len);
    st->rlen += len;
    return 0;
}

#pragma mark - HEV relay handshake (over the SSH channel)

// step 0: send socks greeting offering no-auth AND user/pass (server picks)
// step 1: read method choice (00 = no auth, 02 = user/pass)
// step 2: send RFC1929 creds (only when 02) -> step 3: expect 01 00
// step 4: send FWD UDP request -> step 5: read response
// step 6: done

static size_t hev_build_step0(SStream *st) {
    if (g_cfg.relay_user && g_cfg.relay_pass &&
        *g_cfg.relay_user && *g_cfg.relay_pass) {
        static const uint8_t g[4] = {0x05, 0x02, 0x00, 0x02};  // no-auth + user/pass
        memcpy(st->hev_w, g, 4);
        return 4;
    }
    static const uint8_t g[3] = {0x05, 0x01, 0x00};            // no-auth only
    memcpy(st->hev_w, g, 3);
    return 3;
}

static size_t hev_build_step2(SStream *st) {
    const char *u = g_cfg.relay_user ?: "";
    const char *p = g_cfg.relay_pass ?: "";
    size_t ul = strlen(u), pl = strlen(p);
    if (ul < 1 || ul > 255 || pl < 1 || pl > 255) return 0;
    uint8_t *w = st->hev_w;
    size_t n = 0;
    w[n++] = 0x01;
    w[n++] = (uint8_t)ul;
    memcpy(w + n, u, ul); n += ul;
    w[n++] = (uint8_t)pl;
    memcpy(w + n, p, pl); n += pl;
    return n;
}

static size_t hev_build_step4(SStream *st) {
    static const uint8_t req[10] = {0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    memcpy(st->hev_w, req, 10);
    return 10;
}

/// Drive the HEV handshake. Returns 1 when done, 0 in progress, -1 failure.
static int hev_handshake_drive(SStream *st) {
    for (;;) {
        /* pending handshake write */
        if (st->hev_wlen > st->hev_woff) {
            ssize_t n = libssh2_channel_write_ex(st->ch, 0,
                                                 (char *)st->hev_w + st->hev_woff,
                                                 st->hev_wlen - st->hev_woff);
            if (n == LIBSSH2_ERROR_EAGAIN) return 0;
            if (n < 0) return -1;
            st->hev_woff += (size_t)n;
            if (st->hev_woff < st->hev_wlen) return 0;
            st->hev_wlen = st->hev_woff = 0;
        }

        switch (st->hev_step) {
        case 0:
            st->hev_wlen = hev_build_step0(st);
            st->hev_step = 1;
            st->hneed = 2; st->hlen = 0;
            break;
        case 1:
        case 3: {
            while (st->hlen < st->hneed) {
                ssize_t n = libssh2_channel_read_ex(st->ch, 0,
                                                    (char *)st->hbuf + st->hlen,
                                                    st->hneed - st->hlen);
                if (n == LIBSSH2_ERROR_EAGAIN) return 0;
                if (n <= 0) return -1;
                st->hlen += (size_t)n;
            }
            if (st->hev_step == 1) {
                if (st->hbuf[0] != 0x05) return -1;
                if (st->hbuf[1] == 0x00) {
                    /* server allows no-auth — skip the credential exchange */
                    st->hev_wlen = hev_build_step4(st);
                    st->hev_step = 4;
                } else if (st->hbuf[1] == 0x02) {
                    if (!g_cfg.relay_user || !g_cfg.relay_pass) return -1;
                    st->hev_wlen = hev_build_step2(st);
                    if (st->hev_wlen == 0) return -1;
                    st->hev_step = 2;
                } else {
                    return -1;   // no acceptable method
                }
            } else {
                if (st->hbuf[0] != 0x01 || st->hbuf[1] != 0x00) return -1;
                st->hev_wlen = hev_build_step4(st);
                st->hev_step = 4;
            }
            st->hlen = 0;
            break;
        }
        case 2:
            st->hev_step = 3;
            st->hneed = 2; st->hlen = 0;
            break;
        case 4:
            st->hev_step = 5;
            st->hneed = 4; st->hlen = 0;
            break;
        case 5: {
            /* VER REP RSV ATYP then address + port */
            while (st->hlen < 4) {
                ssize_t n = libssh2_channel_read_ex(st->ch, 0,
                                                    (char *)st->hbuf + st->hlen,
                                                    4 - st->hlen);
                if (n == LIBSSH2_ERROR_EAGAIN) return 0;
                if (n <= 0) return -1;
                st->hlen += (size_t)n;
            }
            if (st->hbuf[0] != 0x05 || st->hbuf[1] != 0x00) return -1;
            size_t addrlen;
            if (st->hbuf[3] == 0x01) addrlen = 4;
            else if (st->hbuf[3] == 0x04) addrlen = 16;
            else if (st->hbuf[3] == 0x03) {
                if (st->hneed == 4) { st->hneed = 5; }
                if (st->hlen < 5) {
                    ssize_t n = libssh2_channel_read_ex(st->ch, 0,
                                                        (char *)st->hbuf + st->hlen,
                                                        5 - st->hlen);
                    if (n == LIBSSH2_ERROR_EAGAIN) return 0;
                    if (n <= 0) return -1;
                    st->hlen += (size_t)n;
                    if (st->hlen < 5) return 0;
                }
                addrlen = st->hbuf[4];
            } else return -1;
            size_t total = 4 + (st->hbuf[3] == 0x03 ? 1 : 0) + addrlen + 2;
            while (st->hlen < total) {
                ssize_t n = libssh2_channel_read_ex(st->ch, 0,
                                                    (char *)st->hbuf + st->hlen,
                                                    total - st->hlen);
                if (n == LIBSSH2_ERROR_EAGAIN) return 0;
                if (n <= 0) return -1;
                st->hlen += (size_t)n;
            }
            return 1;   // relay ready
        }
        default:
            return -1;
        }
    }
}

#pragma mark - socks parsing from the engine

/// Parse greeting/request from the engine. Returns 1 = message complete,
/// 0 = need more bytes, -1 = protocol error.
static int socks_drive(SStream *st) {
    for (;;) {
        while (st->hlen < st->hneed) {
            ssize_t n = read(st->efd, st->hbuf + st->hlen, st->hneed - st->hlen);
            if (n < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
            if (n <= 0) return -1;
            st->hlen += (size_t)n;
        }

        if (st->state == ST_GREET) {
            /* hbuf: VER NMETHODS ... (need was 2) */
            if (st->hneed == 2) {
                if (st->hbuf[0] != 0x05 || st->hbuf[1] == 0) return -1;
                st->hneed = 2 + st->hbuf[1];
                if (st->hlen < st->hneed) continue;
            }
            /* accept: no-auth */
            static const uint8_t accept[2] = {0x05, 0x00};
            if (queue_to_engine(st, accept, 2) < 0) return -1;
            st->hlen = 0;
            st->hneed = 4;
            st->state = ST_REQ;
            return 1;
        }

        /* ST_REQ: VER CMD RSV ATYP [ADDR] PORT — two-step for domains */
        if (st->hneed == 4 && st->hlen >= 4) {
            uint8_t atyp0 = st->hbuf[3];
            if (atyp0 == 0x01) st->hneed = 4 + 4 + 2;
            else if (atyp0 == 0x04) st->hneed = 4 + 16 + 2;
            else if (atyp0 == 0x03) st->hneed = 5;   // read the length byte first
            else return -1;
        }
        if (st->hneed == 5 && st->hbuf[3] == 0x03 && st->hlen >= 5)
            st->hneed = 4 + 1 + st->hbuf[4] + 2;    // now the full domain request
        if (st->hlen < st->hneed) continue;          // read more

        /* full request in hbuf */
        uint8_t cmd = st->hbuf[1];
        uint8_t atyp = st->hbuf[3];
        st->is_udp = (cmd == 0x05);                 // HEV FWD UDP
        if (cmd != 0x01 && cmd != 0x05) return -1;  // CONNECT or FWD UDP only
        if (st->is_udp && !g_cfg.udp_enabled) {
            /* relay disabled in the profile — drop UDP flows cleanly */
            static const uint8_t rej[10] = {0x05,0x05,0x00,0x01,0,0,0,0,0,0};
            queue_to_engine(st, rej, 10);           // REP=5: connection refused
            return -1;
        }

        if (st->is_udp) {
            snprintf(st->dest_host, sizeof(st->dest_host), "%s",
                     g_cfg.relay_host ?: "127.0.0.1");
            st->dest_port = g_cfg.relay_port ?: 1080;
        } else {
            size_t off = 4;
            if (atyp == 0x01) {
                snprintf(st->dest_host, sizeof(st->dest_host), "%u.%u.%u.%u",
                         st->hbuf[off], st->hbuf[off+1], st->hbuf[off+2], st->hbuf[off+3]);
                off += 4;
            } else if (atyp == 0x04) {
                char buf[INET6_ADDRSTRLEN];
                if (!inet_ntop(AF_INET6, st->hbuf + off, buf, sizeof(buf))) return -1;
                snprintf(st->dest_host, sizeof(st->dest_host), "%s", buf);
                off += 16;
            } else {
                uint8_t dl = st->hbuf[off];
                memcpy(st->dest_host, st->hbuf + off + 1, dl);
                st->dest_host[dl] = 0;
                off += 1 + dl;
            }
            st->dest_port = (st->hbuf[off] << 8) | st->hbuf[off+1];
        }
        st->hlen = 0;
        st->state = ST_OPEN;
        return 1;
    }
}

/// Flush pending bytes toward the engine (handshake replies live here too).
static void flush_engine_queue(SStream *st) {
    if (st->rlen > st->roff) {
        ssize_t n = write(st->efd, st->rbuf + st->roff, st->rlen - st->roff);
        if (n > 0) st->roff += (size_t)n;
        if (st->roff == st->rlen) st->rlen = st->roff = 0;
    }
}

#pragma mark - splice

static void splice_drive(SStream *st) {
    /* engine -> channel, unless the session's send queue is full */
    int may_write = txq_pending() < TXQ_PAUSE;
    if (st->wlen > 0 && st->ch && may_write) {
        ssize_t n = libssh2_channel_write_ex(st->ch, 0, (char *)st->wbuf, st->wlen);
        if (n > 0) {
            memmove(st->wbuf, st->wbuf + n, st->wlen - (size_t)n);
            st->wlen -= (size_t)n;
            g_bytes_up += (unsigned long long)n;
            st->up += (unsigned long long)n;
        }
    }
    if (st->wlen == 0 && !st->ch_eof_sent && may_write) {
        int budget = 8;   // fair scheduling: let other streams run
        while (budget-- > 0) {
            ssize_t n = read(st->efd, st->wbuf, sizeof(st->wbuf));
            if (n < 0 && (errno == EAGAIN || errno == EINTR)) break;
            if (n == 0) {
                /* engine closed the flow */
                st->ch_eof_sent = 1;
                if (st->ch) libssh2_channel_send_eof(st->ch);
                break;
            }
            if (n < 0) { st->ch_eof_sent = 1; if (st->ch) libssh2_channel_send_eof(st->ch); break; }
            ssize_t w = st->ch ? libssh2_channel_write_ex(st->ch, 0, (char *)st->wbuf, (size_t)n)
                               : (ssize_t)n;
            if (w > 0) st->up += (unsigned long long)w;
            if (w == n) { /* fully written */ }
            else if (w >= 0 || w == LIBSSH2_ERROR_EAGAIN) {
                size_t done = (w > 0) ? (size_t)w : 0;
                st->wlen = (size_t)n - done;
                if (done > 0) memmove(st->wbuf, st->wbuf + done, st->wlen);
                break;  // backpressure: retry next round
            } else {
                blog(1, "SSH: writing to %s:%d failed (%zd)", st->dest_host, st->dest_port, w);
                st->ch_eof_sent = 1;
                break;
            }
            if (n == 0) break;
        }
    }

    /* channel -> engine */
    if (st->rlen > st->roff) {
        ssize_t n = write(st->efd, st->rbuf + st->roff, st->rlen - st->roff);
        if (n > 0) st->roff += (size_t)n;
        if (st->roff == st->rlen) st->rlen = st->roff = 0;
    }
    if (st->rlen == 0 && st->ch && !st->eng_eof_sent) {
        int budget = 8;
        while (budget-- > 0) {
            ssize_t n = libssh2_channel_read_ex(st->ch, 0, (char *)st->rbuf, sizeof(st->rbuf));
            if (n == LIBSSH2_ERROR_EAGAIN) break;
            if (n > 0) {
                /* data first: the server's last bytes can come with its EOF */
                g_bytes_down += (unsigned long long)n;
                st->down += (unsigned long long)n;
                ssize_t w = write(st->efd, st->rbuf, (size_t)n);
                if (w == n) continue;
                if (w >= 0 || errno == EAGAIN || errno == EINTR) {
                    st->roff = (w > 0) ? (size_t)w : 0;
                    st->rlen = (size_t)n;
                    break;  // engine busy — flush with POLLOUT, then read on
                }
                st->eng_eof_sent = 1;   // the engine side is gone
                break;
            }
            /* 0 = the server's EOF after all its data; < 0 = the channel failed */
            if (n < 0) blog(1, "SSH: reading %s:%d failed (%zd)", st->dest_host, st->dest_port, n);
            st->eng_eof_sent = 1;
            shutdown(st->efd, SHUT_WR);
            break;
        }
    }

    /* closed both ways, and every byte from the server handed to the engine -> dead */
    if (st->ch_eof_sent && st->eng_eof_sent && st->rlen == 0)
        st->state = ST_DEAD;
}

#pragma mark - pump loop

/// Why the session ended, from what libssh2's reader returned and what the socket said
static const char *lost_reason(int rc) {
    if (g_rx_eof || rc == LIBSSH2_ERROR_SOCKET_DISCONNECT) return "the server closed the connection";
    if (g_rx_errno == ECONNRESET) return "the connection was reset";
    if (g_rx_errno == ETIMEDOUT) return "the connection timed out";
    return "the connection was lost";
}

/// Runs the session until it ends; returns why it ended, or NULL when srpssh_stop ended it.
static const char *pump_loop(void) {
    const char *why = NULL;
    int keepalive = g_cfg.keepalive_seconds > 0 ? g_cfg.keepalive_seconds : 15;
    libssh2_keepalive_config(g_sess, 1, (unsigned)keepalive);
    g_last_rx = now_sec();
    while (!g_quit) {
        pthread_mutex_lock(&g_streams_mu);
        int nstreams = 0;
        for (SStream *s = g_streams; s; s = s->next) nstreams++;

        struct pollfd pfds[2 + 256];
        SStream *map[256];
        int nfds = 0;

        pfds[nfds].fd = g_wake[0];
        pfds[nfds].events = POLLIN;
        nfds++;

        int dirs = libssh2_session_block_directions(g_sess);
        short sev = 0;
        if (dirs & LIBSSH2_SESSION_BLOCK_INBOUND) sev |= POLLIN;
        if (dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND) sev |= POLLOUT;
        if (txq_pending() > 0) sev |= POLLOUT;
        pfds[nfds].fd = g_sock;
        pfds[nfds].events = sev | POLLIN;
        nfds++;

        int capped = 0;
        for (SStream *s = g_streams; s && nfds < 258; s = s->next) {
            short ev = 0;
            if (s->state == ST_GREET || s->state == ST_REQ)
                ev |= POLLIN;
            else if (s->state == ST_SPLICE) {
                if (s->wlen < sizeof(s->wbuf) && !s->ch_eof_sent) ev |= POLLIN;
            }
            if (s->rlen > s->roff) ev |= POLLOUT;   // queued handshake/data bytes
            if (ev) {
                pfds[nfds].fd = s->efd;
                pfds[nfds].events = ev;
                map[nfds] = s;
                nfds++;
            } else capped++;
        }
        pthread_mutex_unlock(&g_streams_mu);

        int r = poll(pfds, nfds, 100);
        if (r < 0) {
            if (errno == EINTR) continue;
            why = "the connection was lost";
            break;
        }

        /* adopt streams handed over by the hook */
        pthread_mutex_lock(&g_pending_mu);
        for (int i = 0; i < g_pending_count; i++) {
            SStream *st = stream_new(g_pending_fds[i]);
            if (!st) close(g_pending_fds[i]);
        }
        g_pending_count = 0;
        pthread_mutex_unlock(&g_pending_mu);

        if (pfds[0].revents & POLLIN) {
            uint8_t tmp[64];
            (void)read(g_wake[0], tmp, sizeof(tmp));
        }
        if (pfds[1].revents & POLLNVAL) {
            why = "the connection was lost";
            break;
        }
        if (txq_pending() > 0 && txq_flush(g_sock) < 0) {
            why = lost_reason(0);
            break;
        }

        /* drive state machines — handshakes first, bulk data second, so new
         * flows are not stuck behind queued payload on the single SSH pipe */
        {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec - g_last_stat.tv_sec >= 5 && (g_bytes_up || g_bytes_down)) {
                blog(1, "SSH: stats up=%lluKB down=%lluKB, %d flows, send queue %zuKB, memory %.1f MiB",
                     g_bytes_up / 1024, g_bytes_down / 1024, nstreams, txq_pending() / 1024, footprint_mib());
                if (g_cfg.log_level >= 2) {
                    pthread_mutex_lock(&g_streams_mu);
                    for (SStream *s = g_streams; s; s = s->next)
                        blog(2, "SSH: flow fd %d %s:%d state %d down %llu up %llu to engine %zu to server %zu eof %d/%d",
                             s->efd, s->dest_host, s->dest_port, s->state, s->down, s->up, s->rlen - s->roff, s->wlen,
                             s->ch_eof_sent, s->eng_eof_sent);
                    pthread_mutex_unlock(&g_streams_mu);
                }
                g_last_stat = now;
            }
        }
        pthread_mutex_lock(&g_streams_mu);
        for (int pass = 0; pass < 2; pass++) {
            SStream **pp = &g_streams;
            while (*pp) {
                SStream *s = *pp;
                int dead = 0;
                flush_engine_queue(s);
                if (pass == 1 && s->state != ST_SPLICE) { pp = &s->next; continue; }
                if (pass == 0 && s->state == ST_SPLICE) { pp = &s->next; continue; }
                switch (s->state) {
            case ST_GREET:
            case ST_REQ:
                if (socks_drive(s) < 0) { dead = 1; break; }
                if (s->state != ST_OPEN) break;
                __attribute__((fallthrough));   /* open the channel at once */
            case ST_OPEN: {
                /* libssh2_channel_direct_tcpip_ex keeps one open per session: a second open while the first waited
                 * for the server got the first one's channel, so one connection's data went to another's
                 * destination; and opening one at a time let one slow destination (or the server's slow name
                 * lookup) hold up every new connection. Each open here waits on its own. */
                if (!s->ch) {
                    s->ch = libssh2_channel_direct_tcpip_start(g_sess, s->dest_host, s->dest_port, "127.0.0.1", 0);
                    if (!s->ch) { dead = 1; break; }
                }
                int opened = libssh2_channel_open_result(s->ch);
                if (opened == 0) break;
                if (opened < 0) {
                    s->ch = NULL;   // libssh2 freed it
                    char *emsg = NULL;
                    libssh2_session_last_error(g_sess, &emsg, NULL, 0);
                    blog(1, "SSH: the server could not open %s:%d: %s",
                         s->dest_host, s->dest_port, emsg ?: "?");
                    dead = 1;
                    break;
                }
                g_flows_opened++;
                blog(2, "SSH: flow fd %d opened %s:%d (%s)", s->efd, s->dest_host, s->dest_port, s->is_udp ? "UDP relay" : "TCP");
                if (s->is_udp) {
                    s->state = ST_HEV;
                    s->hev_step = 0;
                    s->hev_wlen = s->hev_woff = 0;
                    s->hlen = 0;
                } else {
                    static const uint8_t ok[10] = {0x05,0x00,0x00,0x01,0,0,0,0,0,0};
                    if (queue_to_engine(s, ok, 10) == 0)
                        s->state = ST_SPLICE;
                    else
                        dead = 1;
                }
                break;
            }
            case ST_HEV: {
                int hr = hev_handshake_drive(s);
                if (hr < 0) {
                    blog(1, "SSH: HEV relay handshake failed at step %d (hlen=%zu need=%zu buf=%02x %02x eof=%d)",
                         s->hev_step, s->hlen, s->hneed,
                         s->hlen > 0 ? s->hbuf[0] : 0, s->hlen > 1 ? s->hbuf[1] : 0,
                         s->ch ? libssh2_channel_eof(s->ch) : -1);
                    dead = 1;
                } else if (hr == 1) {
                    static const uint8_t ok[10] = {0x05,0x00,0x00,0x01,0,0,0,0,0,0};
                    if (queue_to_engine(s, ok, 10) == 0)
                        s->state = ST_SPLICE;
                    else
                        dead = 1;
                }
                break;
            }
            case ST_SPLICE:
                splice_drive(s);
                if (s->state == ST_DEAD) dead = 1;
                break;
            default:
                dead = 1;
                break;
            }

                if (dead) {
                    *pp = s->next;
                    stream_free(s);
                } else {
                    pp = &s->next;
                }
            }
        }
        pthread_mutex_unlock(&g_streams_mu);
        if (g_closing_count > 0) retry_closing();

        /* Packets no channel asked for — the server's keepalive requests (libssh2 answers them), window changes, the
         * server's disconnect — would otherwise wait in the socket while the session is idle */
        if (pfds[1].revents & (POLLIN | POLLERR | POLLHUP)) {
            int rc;
            do rc = _libssh2_transport_read(g_sess); while (rc > 0 && !g_quit);
            if (rc < 0 && rc != LIBSSH2_ERROR_EAGAIN) { why = lost_reason(rc); break; }
        }
        /* Our keepalive: a server that answers nothing for three of them is gone (a dead network path sends no
         * reset, and TCP alone would wait for minutes) */
        int next = 0;
        int krc = libssh2_keepalive_send(g_sess, &next);
        if (krc < 0 && krc != LIBSSH2_ERROR_EAGAIN) { why = lost_reason(krc); break; }
        if (now_sec() - g_last_rx > 3 * keepalive + 5) {
            why = "the server did not answer for too long";
            break;
        }
    }
    return g_quit ? NULL : why;
}

#pragma mark - engine thread

static void *engine_main(void *arg) {
    int tun_fd = *(int *)arg;
    blog(2, "SSH: engine starting (tun fd %d)", tun_fd);
    int r = hev_socks5_tunnel_main_from_str((const unsigned char *)g_engine_conf,
                                            (unsigned int)strlen(g_engine_conf),
                                            tun_fd);
    blog(2, "SSH: engine exited (%d)", r);
    return NULL;
}

#pragma mark - public API

static void *bridge_main(void *arg);

/// The bridge's own copy of a config string in slot i (the previous one is wiped and freed); NULL stays NULL.
static const char *own_string(int i, const char *s) {
    static char *owned[8];
    if (owned[i]) {
        for (volatile char *p = owned[i]; *p; p++) *p = 0;   // passwords do not linger in freed memory
        free(owned[i]);
        owned[i] = NULL;
    }
    if (s) owned[i] = strdup(s);
    return owned[i];
}

int srpssh_start(const SRPSSHBridgeConfig *cfg, int tun_fd,
                 SRPSSHLogCallback log, void *log_ctx,
                 SRPSSHReadyCallback ready, SRPSSHFailCallback fail,
                 SRPSSHGoneCallback gone, void *cb_ctx) {
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, libssh2_global_init);

    g_cfg = *cfg;
    // The session thread reads these for the whole session: own copies, not the caller's buffers (an NSString's
    // UTF8String or a JNI string lives only as long as the call that made it)
    g_cfg.host = own_string(0, cfg->host);
    g_cfg.username = own_string(1, cfg->username);
    g_cfg.password = own_string(2, cfg->password);
    g_cfg.hostkey_sha256 = own_string(3, cfg->hostkey_sha256);
    g_cfg.relay_host = own_string(4, cfg->relay_host);
    g_cfg.relay_user = own_string(5, cfg->relay_user);
    g_cfg.relay_pass = own_string(6, cfg->relay_pass);
    g_cfg.tun_ipv4 = own_string(7, cfg->tun_ipv4);
    g_log = log; g_log_ctx = log_ctx;
    g_ready_cb = ready; g_fail_cb = fail; g_gone_cb = gone; g_cb_ctx = cb_ctx;
    g_quit = 0; g_ready = 0; g_failed = 0;
    g_streams = NULL; g_pending_count = 0;
    g_closing_count = 0;
    g_txq_len = g_txq_off = 0;
    g_bytes_up = 0; g_bytes_down = 0;
    g_rx_eof = 0; g_rx_errno = 0; g_flows_opened = 0;
    g_detail[0] = 0;
    clock_gettime(CLOCK_MONOTONIC, &g_last_stat);

    if (pipe(g_wake) != 0) return -1;
    set_nb(g_wake[0]); set_nb(g_wake[1]);

    /* engine config: socks upstream is placeholder — the stream hook
     * intercepts every connection. UDP-in-TCP = HEV FWD framing. The engine
     * writes its log to stderr, which the tunnel log collects.
     * The names' placeholder addresses come from a /20 of 198.18.0.0/16 picked at random for each session, away from
     * the tunnel's own address (198.18.0.1) and its DNS server (198.18.0.2), which the first names got before: an
     * address the system still caches from an earlier session then belongs to no name instead of to another one. */
    unsigned window = 16 * (1 + arc4random_uniform(15));
    snprintf(g_engine_conf, sizeof(g_engine_conf),
             "tunnel:\n"
             "  mtu: %d\n"
             "  ipv4: %s\n"
             "socks5:\n"
             "  port: 1\n"
             "  address: '127.0.0.1'\n"
             "  udp: 'tcp'\n"
             "  pipeline: true\n"
             "mapdns:\n"
             "  address: 198.18.0.2\n"
             "  port: 53\n"
             "  network: 198.18.%u.0\n"
             "  netmask: 255.255.240.0\n"
             "  cache-size: 2048\n"
             "misc:\n"
             "  log-file: stderr\n"
             "  log-level: %s\n",
             cfg->mtu > 0 ? cfg->mtu : 1500,
             cfg->tun_ipv4 ?: "198.18.0.1", window,
             cfg->log_level >= 2 ? "debug" : cfg->log_level == 1 ? "warn" : "error");

    static int engine_tun_fd;
    engine_tun_fd = tun_fd;

    srp_ssh_stream_open_hook = srpssh_hook_open;
    extern int srpssh_udp_relay_enabled;   // engine global (prefix-exempt)
    srpssh_udp_relay_enabled = cfg->udp_enabled;

    if (pthread_create(&g_pump_thread, NULL, bridge_main, &engine_tun_fd) != 0)
        return -1;
    return 0;
}

void srpssh_stop(void) {
    g_quit = 1;
    wake_pump();
    // The session thread stops the engine it started, then ends: no callback comes after this
    if (g_pump_thread) pthread_join(g_pump_thread, NULL);
    g_pump_thread = 0;
    if (g_wake[0] >= 0) { close(g_wake[0]); close(g_wake[1]); g_wake[0] = g_wake[1] = -1; }
}

#pragma mark - startup (pump thread)

/// Waits until the session socket can go the way libssh2 needs; -1 on a stop or once the connect deadline passed.
static int wait_session(void) {
    int dirs = libssh2_session_block_directions(g_sess);
    short events = 0;
    if (dirs & LIBSSH2_SESSION_BLOCK_INBOUND) events |= POLLIN;
    if (dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND) events |= POLLOUT;
    if (txq_pending() > 0) events |= POLLOUT;
    struct pollfd pfd = { g_sock, events ? events : POLLIN, 0 };
    for (;;) {
        if (g_quit || now_sec() > g_deadline) return -1;
        int r = poll(&pfd, 1, 250);
        if (r < 0 && errno != EINTR) return -1;
        if (r <= 0) continue;
        if (txq_pending() > 0 && txq_flush(g_sock) < 0) return -1;
        return 0;
    }
}

/// libssh2_init wrapper for pthread_once
static void libssh2_global_init(void) { (void)libssh2_init(0); }

/// Connects to the SSH server, every address of the name in turn, each for up to `seconds`; a stop ends it.
/// On failure returns -1 and sets *why to resolve, refused, timeout or unreachable.
static int tcp_connect_server(const char *host, int port, int seconds, const char **why) {
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%d", port);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) { *why = "resolve"; return -1; }
    int fd = -1, refused = 0, timedout = 0;
    for (struct addrinfo *ai = res; ai && !g_quit; ai = ai->ai_next) {
        fd = (int)socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (g_cfg.protect_socket) g_cfg.protect_socket(g_cfg.protect_ctx, fd);
        set_nb(fd);
        int r = connect(fd, ai->ai_addr, ai->ai_addrlen);
        int err = r == 0 ? 0 : errno;
        if (err == EINPROGRESS) {
            struct pollfd pfd = { fd, POLLOUT, 0 };
            err = ETIMEDOUT;
            for (int waited = 0; !g_quit && waited < seconds * 1000; waited += 250) {
                if (poll(&pfd, 1, 250) > 0) {
                    socklen_t len = sizeof(err);
                    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0) err = errno;
                    break;
                }
            }
        }
        if (err == 0) break;
        if (err == ECONNREFUSED) refused = 1;
        if (err == ETIMEDOUT) timedout = 1;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) *why = refused ? "refused" : timedout ? "timeout" : "unreachable";
    return fd;
}

static int session_handshake(void) {
    int rc;
    while ((rc = libssh2_session_handshake(g_sess, g_sock)) == LIBSSH2_ERROR_EAGAIN) {
        if (wait_session() < 0) return -1;
    }
    return rc;
}

static const char *hostkey_type_name(int type) {
    switch (type) {
        case LIBSSH2_HOSTKEY_TYPE_ED25519: return "ED25519";
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_256:
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_384:
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_521: return "ECDSA";
        case LIBSSH2_HOSTKEY_TYPE_RSA: return "RSA";
        default: return "unknown type";
    }
}

int srpssh_pin_normalize(const char *text, char *out, unsigned long outlen) {
    const char *p = text ? strstr(text, "SHA256:") : NULL;
    if (!p || outlen < 8) return -1;
    size_t n = 0;
    for (const char *c = p; *c && n + 1 < outlen; c++) {
        if (c - p >= 7 && !(isalnum((unsigned char)*c) || *c == '+' || *c == '/')) break;   // "=" padding, space, ")"
        out[n++] = *c;
    }
    out[n] = 0;
    return n > 7 ? 0 : -1;
}

/// The server's host key as OpenSSH prints it ("SHA256:" and the unpadded base64 of its SHA-256), into out[56]
static int hostkey_fingerprint(char *out, int *type) {
    size_t len = 0;
    *type = LIBSSH2_HOSTKEY_TYPE_UNKNOWN;
    if (!libssh2_session_hostkey(g_sess, &len, type)) return -1;
    const unsigned char *h = (const unsigned char *)libssh2_hostkey_hash(g_sess, LIBSSH2_HOSTKEY_HASH_SHA256);
    if (!h) return -1;
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int o = snprintf(out, 8, "SHA256:");
    for (int i = 0; i < 30; i += 3) {
        unsigned v = (h[i] << 16) | (h[i+1] << 8) | h[i+2];
        out[o++] = b64[v >> 18];
        out[o++] = b64[(v >> 12) & 63];
        out[o++] = b64[(v >> 6) & 63];
        out[o++] = b64[v & 63];
    }
    unsigned v = (h[30] << 16) | (h[31] << 8);
    out[o++] = b64[v >> 18];
    out[o++] = b64[(v >> 12) & 63];
    out[o++] = b64[(v >> 6) & 63];
    out[o] = 0;
    return 0;
}

/// Logs the server's key (it is public) and checks the pin; -1 on a mismatch, with the presented key in g_detail.
static int verify_hostkey(void) {
    char got[56];
    int type;
    if (hostkey_fingerprint(got, &type) != 0) {
        snprintf(g_detail, sizeof(g_detail), "the server's host key could not be read");
        return -1;
    }
    blog(0, "SSH: server host key %s %s", hostkey_type_name(type), got);
    if (!g_cfg.hostkey_sha256 || !*g_cfg.hostkey_sha256) return 0;  // not pinned
    char pin[64];
    if (srpssh_pin_normalize(g_cfg.hostkey_sha256, pin, sizeof(pin)) != 0 || strcmp(pin, got) != 0) {
        snprintf(g_detail, sizeof(g_detail), "%s %s", hostkey_type_name(type), got);
        blog(0, "SSH: the host key does not match the pinned one");
        return -1;
    }
    return 0;
}

/// keyboard-interactive: every prompt (PAM asks "Password:") gets the profile's password
static void kbd_answer(const char *name, int name_len, const char *instruction, int instruction_len,
                       int num_prompts, const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
                       LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses, void **abstract) {
    (void)name; (void)name_len; (void)instruction; (void)instruction_len; (void)prompts; (void)abstract;
    const char *p = g_cfg.password ?: "";
    for (int i = 0; i < num_prompts; i++) {
        responses[i].text = strdup(p);   // libssh2 frees it
        responses[i].length = responses[i].text ? (unsigned)strlen(p) : 0;
    }
}

/// 0 = logged in; SRPSSH_ERR_AUTH = the server refused the user name or password; SRPSSH_ERR_AUTH_METHOD = it
/// takes no password for this user (g_detail: what it offers); -1 = the connection failed meanwhile.
static int userauth(void) {
    const char *u = g_cfg.username ?: "";
    const char *p = g_cfg.password ?: "";
    char *methods;
    while (!(methods = libssh2_userauth_list(g_sess, u, (unsigned)strlen(u)))) {
        if (libssh2_userauth_authenticated(g_sess)) return 0;   // the server needs no password ("none")
        if (libssh2_session_last_errno(g_sess) != LIBSSH2_ERROR_EAGAIN || wait_session() < 0) return -1;
    }
    int password = strstr(methods, "password") != NULL;
    int keyboard = strstr(methods, "keyboard-interactive") != NULL;
    if (!password && !keyboard) {
        snprintf(g_detail, sizeof(g_detail), "%s", methods);
        return SRPSSH_ERR_AUTH_METHOD;
    }
    int rc;
    if (password) {
        while ((rc = libssh2_userauth_password_ex(g_sess, u, (unsigned)strlen(u), p, (unsigned)strlen(p), NULL))
               == LIBSSH2_ERROR_EAGAIN) {
            if (wait_session() < 0) return -1;
        }
    } else {
        blog(1, "SSH: logging in with keyboard-interactive (the server offers %s)", methods);
        while ((rc = libssh2_userauth_keyboard_interactive_ex(g_sess, u, (unsigned)strlen(u), kbd_answer))
               == LIBSSH2_ERROR_EAGAIN) {
            if (wait_session() < 0) return -1;
        }
    }
    if (rc == 0) return 0;
    if (rc == LIBSSH2_ERROR_AUTHENTICATION_FAILED || rc == LIBSSH2_ERROR_PASSWORD_EXPIRED ||
        rc == LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED) return SRPSSH_ERR_AUTH;
    return -1;
}

/// Opens a direct-tcpip channel; NULL with *refused set when the server answered with a refusal (not a timeout).
static LIBSSH2_CHANNEL *open_channel(const char *host, int port, char **emsg) {
    for (;;) {
        LIBSSH2_CHANNEL *ch = libssh2_channel_direct_tcpip_ex(g_sess, host, port, "127.0.0.1", 0);
        if (ch) return ch;
        if (libssh2_session_last_errno(g_sess) != LIBSSH2_ERROR_EAGAIN) {
            libssh2_session_last_error(g_sess, emsg, NULL, 0);
            return NULL;
        }
        *emsg = NULL;
        if (wait_session() < 0) return NULL;
    }
}

static void close_channel(LIBSSH2_CHANNEL *ch) {
    libssh2_channel_send_eof(ch);
    for (int i = 0; i < 10; i++) {   // orderly close: avoid local id reuse races
        if (libssh2_channel_close(ch) != LIBSSH2_ERROR_EAGAIN) break;
        if (wait_session() < 0) break;
    }
    libssh2_channel_free(ch);
}

/// A channel to 127.0.0.1:9 on the server, where nothing listens: "connect failed" means this user may forward TCP,
/// "administratively prohibited" means the server forbids it (AllowTcpForwarding, PermitOpen), which would leave a
/// VPN that carries nothing. 0 = allowed, 1 = forbidden, -1 = the connection failed meanwhile.
static int forwarding_preflight(void) {
    char *emsg = NULL;
    LIBSSH2_CHANNEL *ch = open_channel("127.0.0.1", 9, &emsg);
    if (ch) { close_channel(ch); return 0; }   // something answers there: forwarding works
    if (!emsg) return -1;
    return strstr(emsg, "administratively prohibited") ? 1 : 0;
}

/// Open a channel to the HEV relay and prove the FWD UDP handshake works.
static int relay_preflight(void) {
    char *emsg = NULL;
    LIBSSH2_CHANNEL *ch = open_channel(g_cfg.relay_host ?: "127.0.0.1", g_cfg.relay_port ?: 1080, &emsg);
    if (!ch) {
        snprintf(g_detail, sizeof(g_detail), "%s", emsg ?: "no answer");
        return -1;
    }
    SStream tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.ch = ch;
    tmp.hev_step = 0;
    int ok = -1;
    for (int i = 0; i < 200; i++) {   // bounded, and by the connect deadline
        int hr = hev_handshake_drive(&tmp);
        if (hr == 1) { ok = 0; break; }
        if (hr < 0) { snprintf(g_detail, sizeof(g_detail), "the relay refused the UDP request"); break; }
        if (wait_session() < 0) break;
    }
    close_channel(ch);
    return ok;
}

static void *bridge_main(void *arg) {
    int engine_tun_fd = *(int *)arg;
    SRPSSHError err = SRPSSH_ERR_NONE;
    const char *why = NULL;
    const char *lost = NULL;
    // Connect, login and the checks must finish in time: a server that takes the connection and then says nothing
    // must not hold the start
    g_deadline = now_sec() + 15 + 20;

    g_sock = tcp_connect_server(g_cfg.host, g_cfg.port, 15, &why);
    if (g_sock < 0) { err = SRPSSH_ERR_CONNECT; snprintf(g_detail, sizeof(g_detail), "%s", why); goto fail; }
    g_deadline = now_sec() + 20;

    /* latency: no Nagle on the SSH transport; keep the session alive */
    {
        int one = 1;
        setsockopt(g_sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        setsockopt(g_sock, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
        int bsz = 1024 * 1024;
        setsockopt(g_sock, SOL_SOCKET, SO_SNDBUF, &bsz, sizeof(bsz));
        setsockopt(g_sock, SOL_SOCKET, SO_RCVBUF, &bsz, sizeof(bsz));
    }

    g_sess = libssh2_session_init_ex(NULL, NULL, NULL, NULL);
    if (!g_sess) { err = SRPSSH_ERR_HANDSHAKE; goto fail; }
    libssh2_session_set_blocking(g_sess, 0);
    libssh2_session_callback_set2(g_sess, LIBSSH2_CALLBACK_RECV, (libssh2_cb_generic *)srp_recv);
    libssh2_session_callback_set2(g_sess, LIBSSH2_CALLBACK_SEND, (libssh2_cb_generic *)srp_send);
    // OpenSSH's order: the key a server shows first in `ssh` (ED25519 on current servers) is the one the app checks
    libssh2_session_method_pref(g_sess, LIBSSH2_METHOD_HOSTKEY,
                                "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,"
                                "rsa-sha2-512,rsa-sha2-256,ssh-rsa");

    if (session_handshake() != 0) {
        err = SRPSSH_ERR_HANDSHAKE;
        char *emsg = NULL;
        libssh2_session_last_error(g_sess, &emsg, NULL, 0);
        snprintf(g_detail, sizeof(g_detail), "%s", g_quit ? "" : now_sec() > g_deadline ? "timeout" : (emsg ?: ""));
        goto fail;
    }
    if (verify_hostkey() != 0) { err = SRPSSH_ERR_HOSTKEY; goto fail; }
    int auth = userauth();
    if (auth == SRPSSH_ERR_AUTH || auth == SRPSSH_ERR_AUTH_METHOD) { err = (SRPSSHError)auth; goto fail; }
    if (auth != 0) { err = SRPSSH_ERR_HANDSHAKE; snprintf(g_detail, sizeof(g_detail), "the login did not finish"); goto fail; }
    blog(0, "SSH: logged in as %s", g_cfg.username);

    int forwarding = forwarding_preflight();
    if (forwarding == 1) { err = SRPSSH_ERR_FORWARDING; goto fail; }
    if (forwarding < 0) { err = SRPSSH_ERR_HANDSHAKE; snprintf(g_detail, sizeof(g_detail), "the server stopped answering"); goto fail; }

    if (g_cfg.udp_enabled) {
        if (relay_preflight() != 0) { err = SRPSSH_ERR_RELAY; goto fail; }
        blog(0, "SSH: UDP relay ready");
    }

    /* start the packet engine now that SSH is fully up */
    if (pthread_create(&g_engine_thread, NULL, engine_main, &engine_tun_fd) != 0) {
        g_engine_thread = 0;
        err = SRPSSH_ERR_HANDSHAKE; snprintf(g_detail, sizeof(g_detail), "the packet engine did not start"); goto fail;
    }

    g_ready = 1;
    if (g_ready_cb) g_ready_cb(g_cb_ctx);

    lost = pump_loop();
    if (lost) {
        blog(0, "SSH: session ended: %s", lost);
        if (g_gone_cb) g_gone_cb(g_cb_ctx, lost);
    }
    goto out;

fail:
    g_failed = 1;
    // A stop ends a connect that is still going on: that is no failure to report
    if (!g_quit && g_fail_cb) g_fail_cb(g_cb_ctx, err, g_detail);
out:
    /* tear down everything we own: the engine first, so no flow reaches the streams freed below */
    if (g_engine_thread) {
        hev_socks5_tunnel_quit();
        pthread_join(g_engine_thread, NULL);
        g_engine_thread = 0;
    }
    pthread_mutex_lock(&g_pending_mu);
    for (int i = 0; i < g_pending_count; i++) close(g_pending_fds[i]);
    g_pending_count = 0;
    pthread_mutex_unlock(&g_pending_mu);
    pthread_mutex_lock(&g_streams_mu);
    while (g_streams) {
        SStream *s = g_streams;
        g_streams = s->next;
        stream_free(s);
    }
    pthread_mutex_unlock(&g_streams_mu);

    if (g_sess) {
        // a lost connection gets no goodbye: its socket would only block
        if (!lost) libssh2_session_disconnect_ex(g_sess, SSH_DISCONNECT_BY_APPLICATION, "bye", "");
        libssh2_session_free(g_sess);   // frees the channels still closing too
        g_sess = NULL;
    }
    g_closing_count = 0;
    if (g_sock >= 0) { close(g_sock); g_sock = -1; }
    return NULL;
}
