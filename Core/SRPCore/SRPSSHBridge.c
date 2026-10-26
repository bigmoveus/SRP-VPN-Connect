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

#include <libssh2.h>

/* Engine entry points and the stream hook — all renamed to srpssh_* by the
 * prefix header (see SSH/build_engine.sh). */
#include "srpssh-prefix.h"
#include "hev-main.h"
#include "srp-ssh-hook.h"

#pragma mark - stream state

enum {
    ST_GREET = 0,   // reading the engine's SOCKS greeting
    ST_REQ,         // reading the engine's SOCKS request
    ST_OPEN,        // opening the SSH channel (EAGAIN retry)
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

#pragma mark - logging

static void blog(const char *fmt, ...);
static void libssh2_global_init(void);

static void blog(const char *fmt, ...) {
    if (!g_log) return;
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    g_log(g_log_ctx, line);
}

#pragma mark - small helpers

static int set_nb(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
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
    if (st->efd >= 0) close(st->efd);
    if (st->ch) {
        libssh2_channel_close(st->ch);
        libssh2_channel_free(st->ch);
    }
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
    /* engine -> channel */
    if (st->wlen > 0 && st->ch) {
        ssize_t n = libssh2_channel_write_ex(st->ch, 0, (char *)st->wbuf, st->wlen);
        if (n > 0) {
            memmove(st->wbuf, st->wbuf + n, st->wlen - (size_t)n);
            st->wlen -= (size_t)n;
            g_bytes_up += (unsigned long long)n;
        }
    }
    if (st->wlen == 0 && !st->ch_eof_sent) {
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
            if (w == n) { /* fully written */ }
            else if (w >= 0 || w == LIBSSH2_ERROR_EAGAIN) {
                size_t done = (w > 0) ? (size_t)w : 0;
                st->wlen = (size_t)n - done;
                if (done > 0) memmove(st->wbuf, st->wbuf + done, st->wlen);
                break;  // backpressure: retry next round
            } else {
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
            if (n == 0 || libssh2_channel_eof(st->ch)) {
                st->eng_eof_sent = 1;
                shutdown(st->efd, SHUT_WR);
                break;
            }
            if (n < 0) { st->eng_eof_sent = 1; shutdown(st->efd, SHUT_WR); break; }
            g_bytes_down += (unsigned long long)n;
            ssize_t w = write(st->efd, st->rbuf, (size_t)n);
            if (w == n) continue;
            if (w >= 0 || (w < 0 && (errno == EAGAIN || errno == EINTR))) {
                size_t done = (w > 0) ? (size_t)w : 0;
                st->roff = done;
                st->rlen = (size_t)n;
                break;  // engine busy — flush with POLLOUT
            }
            st->eng_eof_sent = 1;
            break;
        }
    }

    /* fully closed both ways -> dead */
    if ((st->ch_eof_sent && libssh2_channel_eof(st->ch)) ||
        (st->ch && libssh2_channel_eof(st->ch) && st->eng_eof_sent))
        st->state = ST_DEAD;
}

#pragma mark - pump loop

static void pump_loop(void) {
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
        pfds[nfds].fd = g_sock;
        pfds[nfds].events = sev ? sev : POLLIN;
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
        if (r > 0 && nfds > 1 && (pfds[1].revents & (POLLERR | POLLHUP | POLLNVAL))) {
            blog("SSH: session socket error");
            break;
        }

        /* drive state machines — handshakes first, bulk data second, so new
         * flows are not stuck behind queued payload on the single SSH pipe */
        {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec - g_last_stat.tv_sec >= 5 && (g_bytes_up || g_bytes_down)) {
                blog("SSH: stats up=%lluKB down=%lluKB", g_bytes_up / 1024, g_bytes_down / 1024);
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
                if (socks_drive(s) < 0) dead = 1;
                if (!dead && s->state == ST_OPEN) {
                    s->ch = libssh2_channel_direct_tcpip_ex(g_sess, s->dest_host,
                                                            s->dest_port,
                                                            "127.0.0.1", 0);
                    if (!s->ch) {
                        int rc = libssh2_session_last_errno(g_sess);
                        if (rc != LIBSSH2_ERROR_EAGAIN) {
                            blog("SSH: channel open to %s:%d failed (%d)",
                                 s->dest_host, s->dest_port, rc);
                            dead = 1;
                        }
                    } else if (s->is_udp) {
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
                }
                break;
            case ST_OPEN:
                s->ch = libssh2_channel_direct_tcpip_ex(g_sess, s->dest_host,
                                                        s->dest_port,
                                                        "127.0.0.1", 0);
                if (!s->ch) {
                    int rc = libssh2_session_last_errno(g_sess);
                    if (rc != LIBSSH2_ERROR_EAGAIN) {
                        char *emsg = NULL;
                        libssh2_session_last_error(g_sess, &emsg, NULL, 0);
                        blog("SSH: channel open to %s:%d failed: %s",
                             s->dest_host, s->dest_port, emsg ?: "?");
                        dead = 1;
                    }
                } else if (s->is_udp) {
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
            case ST_HEV: {
                int hr = hev_handshake_drive(s);
                if (hr < 0) {
                    blog("SSH: HEV relay handshake failed at step %d (hlen=%zu need=%zu buf=%02x %02x eof=%d)",
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
    }
}

#pragma mark - engine thread

static void *engine_main(void *arg) {
    int tun_fd = *(int *)arg;
    blog("SSH: engine starting (tun fd %d)", tun_fd);
    int r = hev_socks5_tunnel_main_from_str((const unsigned char *)g_engine_conf,
                                            (unsigned int)strlen(g_engine_conf),
                                            tun_fd);
    blog("SSH: engine exited (%d)", r);
    return NULL;
}

#pragma mark - public API

static void *bridge_main(void *arg);

int srpssh_start(const SRPSSHBridgeConfig *cfg, int tun_fd,
                 SRPSSHLogCallback log, void *log_ctx,
                 SRPSSHReadyCallback ready, SRPSSHFailCallback fail,
                 SRPSSHGoneCallback gone, void *cb_ctx) {
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, libssh2_global_init);

    g_cfg = *cfg;
    g_log = log; g_log_ctx = log_ctx;
    g_ready_cb = ready; g_fail_cb = fail; g_gone_cb = gone; g_cb_ctx = cb_ctx;
    g_quit = 0; g_ready = 0; g_failed = 0;
    g_streams = NULL; g_pending_count = 0;
    g_bytes_up = 0; g_bytes_down = 0;
    clock_gettime(CLOCK_MONOTONIC, &g_last_stat);

    if (pipe(g_wake) != 0) return -1;
    set_nb(g_wake[0]); set_nb(g_wake[1]);

    /* engine config: socks upstream is placeholder — the stream hook
     * intercepts every connection. UDP-in-TCP = HEV FWD framing. */
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
             "  network: 198.18.0.0\n"
             "  netmask: 255.255.0.0\n"
             "  cache-size: 2048\n"
             "misc:\n"
             "  log-file: stderr\n"
             "  log-level: %s\n",
             cfg->mtu > 0 ? cfg->mtu : 1500,
             cfg->tun_ipv4 ?: "198.18.0.1",
             "debug");   // TEMP: engine debug while bring-up

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
    if (g_engine_thread) {
        hev_socks5_tunnel_quit();
        pthread_join(g_engine_thread, NULL);
        g_engine_thread = 0;
    }
    if (g_pump_thread) pthread_join(g_pump_thread, NULL);
    if (g_wake[0] >= 0) { close(g_wake[0]); close(g_wake[1]); g_wake[0] = g_wake[1] = -1; }
    g_pump_thread = 0;
}

#pragma mark - startup (pump thread)

static int wait_socket(int events) {
    struct pollfd pfd = { g_sock, (short)events, 0 };
    for (;;) {
        if (g_quit) return -1;
        int r = poll(&pfd, 1, 500);
        if (r > 0) return 0;
        if (r < 0 && errno != EINTR) return -1;
    }
}

/// libssh2_init wrapper for pthread_once
static void libssh2_global_init(void) { (void)libssh2_init(0); }

static int tcp_connect_server(const char *host, int port) {
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%d", port);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = (int)socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int session_handshake(void) {
    int rc;
    while ((rc = libssh2_session_handshake(g_sess, g_sock)) == LIBSSH2_ERROR_EAGAIN) {
        int dirs = libssh2_session_block_directions(g_sess);
        if (wait_socket(dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND ? POLLOUT : POLLIN) < 0)
            return -1;
    }
    return rc;
}

static int verify_hostkey(void) {
    if (!g_cfg.hostkey_sha256 || !*g_cfg.hostkey_sha256) return 0;  // not pinned
    const char *hash = libssh2_hostkey_hash(g_sess, LIBSSH2_HOSTKEY_HASH_SHA256);
    if (!hash) return -1;
    /* base64 of the raw 32-byte hash, compared with the "SHA256:..." form */
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const unsigned char *h = (const unsigned char *)hash;
    char out[45];
    int o = 0;
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
    char expect[56];
    snprintf(expect, sizeof(expect), "SHA256:%s", out);
    if (strcmp(expect, g_cfg.hostkey_sha256) != 0) {
        blog("SSH: host key mismatch (got %s)", expect);
        return -1;
    }
    return 0;
}

static int userauth(void) {
    const char *u = g_cfg.username ?: "";
    const char *p = g_cfg.password ?: "";
    int rc;
    while ((rc = libssh2_userauth_password_ex(g_sess, u, (unsigned)strlen(u),
                                              p, (unsigned)strlen(p), NULL))
           == LIBSSH2_ERROR_EAGAIN) {
        int dirs = libssh2_session_block_directions(g_sess);
        if (wait_socket(dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND ? POLLOUT : POLLIN) < 0)
            return -1;
    }
    return rc;
}

/// Open a channel to the HEV relay and prove the FWD UDP handshake works.
static int relay_preflight(void) {
    LIBSSH2_CHANNEL *ch = NULL;
    for (;;) {
        ch = libssh2_channel_direct_tcpip_ex(g_sess,
                                             g_cfg.relay_host ?: "127.0.0.1",
                                             g_cfg.relay_port ?: 1080,
                                             "127.0.0.1", 0);
        if (ch) break;
        int rc = libssh2_session_last_errno(g_sess);
        if (rc != LIBSSH2_ERROR_EAGAIN) return -1;
        int dirs = libssh2_session_block_directions(g_sess);
        if (wait_socket(dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND ? POLLOUT : POLLIN) < 0)
            return -1;
    }
    SStream tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.ch = ch;
    tmp.hev_step = 0;
    int ok = -1;
    for (int i = 0; i < 200; i++) {   // bounded: ~100s worst case
        int hr = hev_handshake_drive(&tmp);
        if (hr == 1) { ok = 0; break; }
        if (hr < 0) break;
        int dirs = libssh2_session_block_directions(g_sess);
        if (wait_socket(dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND ? POLLOUT : POLLIN) < 0)
            break;
    }
    libssh2_channel_send_eof(ch);
    for (int i = 0; i < 10; i++) {   // orderly close: avoid local id reuse races
        if (libssh2_channel_close(ch) != LIBSSH2_ERROR_EAGAIN) break;
        int dirs = libssh2_session_block_directions(g_sess);
        if (wait_socket(dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND ? POLLOUT : POLLIN) < 0) break;
    }
    libssh2_channel_free(ch);
    return ok;
}

static void *bridge_main(void *arg) {
    int engine_tun_fd = *(int *)arg;
    SRPSSHError err = SRPSSH_ERR_NONE;
    const char *detail = NULL;

    g_sock = tcp_connect_server(g_cfg.host, g_cfg.port);
    if (g_sock < 0) { err = SRPSSH_ERR_CONNECT; detail = "TCP connect failed"; goto fail; }

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

    if (session_handshake() != 0) { err = SRPSSH_ERR_HANDSHAKE; detail = "SSH handshake failed"; goto fail; }
    if (verify_hostkey() != 0) { err = SRPSSH_ERR_HOSTKEY; detail = "SSH host key mismatch"; goto fail; }
    if (userauth() != 0) { err = SRPSSH_ERR_AUTH; detail = "SSH authentication failed"; goto fail; }
    blog("SSH: authenticated as %s@%s:%d", g_cfg.username, g_cfg.host, g_cfg.port);

    if (g_cfg.udp_enabled) {
        if (relay_preflight() != 0) {
            err = SRPSSH_ERR_RELAY;
            detail = "UDP relay (HEV) unavailable or rejected the credentials";
            goto fail;
        }
        blog("SSH: HEV UDP relay verified");
    }

    /* start the packet engine now that SSH is fully up */
    if (pthread_create(&g_engine_thread, NULL, engine_main, &engine_tun_fd) != 0) {
        err = SRPSSH_ERR_HANDSHAKE; detail = "engine start failed"; goto fail;
    }

    g_ready = 1;
    if (g_ready_cb) g_ready_cb(g_cb_ctx);
    blog("SSH: session up");

    pump_loop();

    if (!g_quit && !g_failed) {
        /* session lost unexpectedly */
        if (g_gone_cb) g_gone_cb(g_cb_ctx);
    }
    goto out;

fail:
    g_failed = 1;
    if (g_fail_cb) g_fail_cb(g_cb_ctx, err, detail);
out:
    /* tear down everything we own */
    pthread_mutex_lock(&g_streams_mu);
    while (g_streams) {
        SStream *s = g_streams;
        g_streams = s->next;
        stream_free(s);
    }
    pthread_mutex_unlock(&g_streams_mu);

    if (g_sess) {
        libssh2_session_disconnect_ex(g_sess, SSH_DISCONNECT_BY_APPLICATION, "bye", "");
        libssh2_session_free(g_sess);
        g_sess = NULL;
    }
    if (g_sock >= 0) { close(g_sock); g_sock = -1; }
    return NULL;
}
