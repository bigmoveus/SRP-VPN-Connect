// Aether for Android (libsrpaether.so): the engine of our fork (github.com/bigmoveus/Aether, built by cargo-ndk into
// libaether.a) through its C interface, the hev-socks5-tunnel packet engine (iOS/SSH/upstream, the same sources and
// srpssh_ names as libsrpssh.so, kept inside this library) on the VpnService TUN, the engine's and hev's stderr lines
// for AetherClient.kt, and the SOCKS5 test connection of SRPAetherClient.m.
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

extern char *aether_version(void);
extern char *aether_identity_open(const char *payload);
extern char *aether_scan_start(uint64_t identity, const char *payload);
extern char *aether_verify_start(uint64_t identity, const char *payload);
extern char *aether_tunnel_start(uint64_t identity, const char *payload);
extern char *aether_job_poll(uint64_t id);
extern char *aether_job_cancel(uint64_t id);
extern char *aether_job_free(uint64_t id);
extern void aether_string_free(char *s);

extern int srpssh_hev_socks5_tunnel_main_from_str(const unsigned char *conf, unsigned int len, int tun_fd);
extern void srpssh_hev_socks5_tunnel_quit(void);

#define CALL_VERSION 0
#define CALL_IDENTITY_OPEN 1
#define CALL_VERIFY_START 2
#define CALL_SCAN_START 3
#define CALL_TUNNEL_START 4
#define CALL_JOB_POLL 5
#define CALL_JOB_CANCEL 6
#define CALL_JOB_FREE 7

static jstring take_reply(JNIEnv *env, char *raw) {
    if (!raw) return NULL;
    jstring reply = (*env)->NewStringUTF(env, raw);
    aether_string_free(raw);
    return reply;
}

// One engine call; every reply of the engine is JSON (ffi.rs)
JNIEXPORT jstring JNICALL Java_tr_com_srp_vpn_AetherNative_call(JNIEnv *env, jclass c, jint fn, jlong id, jstring payload) {
    const char *text = payload ? (*env)->GetStringUTFChars(env, payload, NULL) : NULL;
    char *raw = NULL;
    switch (fn) {
        case CALL_VERSION: raw = aether_version(); break;
        case CALL_IDENTITY_OPEN: raw = aether_identity_open(text); break;
        case CALL_VERIFY_START: raw = aether_verify_start((uint64_t)id, text); break;
        case CALL_SCAN_START: raw = aether_scan_start((uint64_t)id, text); break;
        case CALL_TUNNEL_START: raw = aether_tunnel_start((uint64_t)id, text); break;
        case CALL_JOB_POLL: raw = aether_job_poll((uint64_t)id); break;
        case CALL_JOB_CANCEL: raw = aether_job_cancel((uint64_t)id); break;
        case CALL_JOB_FREE: raw = aether_job_free((uint64_t)id); break;
    }
    if (text) (*env)->ReleaseStringUTFChars(env, payload, text);
    return take_reply(env, raw);
}

// The engine reads its settings from the environment (AETHER_*, RUST_LOG); null unsets
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_AetherNative_setenv(JNIEnv *env, jclass c, jstring key, jstring value) {
    const char *k = (*env)->GetStringUTFChars(env, key, NULL);
    if (value) {
        const char *v = (*env)->GetStringUTFChars(env, value, NULL);
        setenv(k, v, 1);
        (*env)->ReleaseStringUTFChars(env, value, v);
    } else {
        unsetenv(k);
    }
    (*env)->ReleaseStringUTFChars(env, key, k);
}

// --- stderr: the engine (env_logger) and hev write their lines there; a pipe hands them to Kotlin -------------------

#define LOG_QUEUE 512
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t log_ready = PTHREAD_COND_INITIALIZER;
static char *log_lines[LOG_QUEUE];
static int log_head, log_count;
static int log_pipe[2] = {-1, -1};
static int saved_stderr = -1;
static pthread_t log_thread;

static void queue_line(const char *line, size_t length) {
    char *copy = malloc(length + 1);
    if (!copy) return;
    memcpy(copy, line, length);
    copy[length] = 0;
    pthread_mutex_lock(&log_lock);
    if (log_count == LOG_QUEUE) {   // nobody reads: the oldest line goes
        free(log_lines[log_head]);
        log_head = (log_head + 1) % LOG_QUEUE;
        log_count--;
    }
    log_lines[(log_head + log_count) % LOG_QUEUE] = copy;
    log_count++;
    pthread_cond_signal(&log_ready);
    pthread_mutex_unlock(&log_lock);
}

static void *log_reader(void *arg) {
    int fd = (int)(intptr_t)arg;
    char buffer[4096];
    size_t used = 0;
    for (;;) {
        ssize_t n = read(fd, buffer + used, sizeof(buffer) - used);
        if (n <= 0) break;
        used += (size_t)n;
        size_t start = 0;
        for (size_t i = 0; i < used; i++) {
            if (buffer[i] == '\n') {
                if (i > start) queue_line(buffer + start, i - start);
                start = i + 1;
            }
        }
        if (start == 0 && used == sizeof(buffer)) {   // a line longer than the buffer: hand it over in pieces
            queue_line(buffer, used);
            used = 0;
        } else {
            memmove(buffer, buffer + start, used - start);
            used -= start;
        }
    }
    close(fd);
    return NULL;
}

JNIEXPORT void JNICALL Java_tr_com_srp_vpn_AetherNative_captureStderr(JNIEnv *env, jclass c) {
    if (log_pipe[1] >= 0) return;
    if (pipe(log_pipe) != 0) return;
    saved_stderr = dup(STDERR_FILENO);
    dup2(log_pipe[1], STDERR_FILENO);
    setvbuf(stderr, NULL, _IOLBF, 0);
    pthread_create(&log_thread, NULL, log_reader, (void *)(intptr_t)log_pipe[0]);
    pthread_detach(log_thread);
}

// The next stderr line, or null after timeoutMs
JNIEXPORT jstring JNICALL Java_tr_com_srp_vpn_AetherNative_nextLog(JNIEnv *env, jclass c, jint timeoutMs) {
    pthread_mutex_lock(&log_lock);
    if (log_count == 0 && timeoutMs > 0) {
        struct timespec until;
        clock_gettime(CLOCK_REALTIME, &until);
        until.tv_sec += timeoutMs / 1000;
        until.tv_nsec += (long)(timeoutMs % 1000) * 1000000L;
        if (until.tv_nsec >= 1000000000L) {
            until.tv_sec++;
            until.tv_nsec -= 1000000000L;
        }
        pthread_cond_timedwait(&log_ready, &log_lock, &until);
    }
    char *line = NULL;
    if (log_count > 0) {
        line = log_lines[log_head];
        log_head = (log_head + 1) % LOG_QUEUE;
        log_count--;
    }
    pthread_mutex_unlock(&log_lock);
    if (!line) return NULL;
    jstring text = (*env)->NewStringUTF(env, line);
    free(line);
    return text;
}

// --- hev on the VpnService TUN ----------------------------------------------------------------------------------------

static pthread_t hev_thread;
static int hev_running;
static char *hev_conf;
static int hev_fd = -1;

static void *hev_main(void *arg) {
    srpssh_hev_socks5_tunnel_main_from_str((const unsigned char *)hev_conf, (unsigned int)strlen(hev_conf), hev_fd);
    return NULL;
}

// hev on its own copy of the TUN fd with the given configuration (the iOS app's, SRPAetherClient.m startHevLocked)
JNIEXPORT jint JNICALL Java_tr_com_srp_vpn_AetherNative_hevStart(JNIEnv *env, jclass c, jstring conf, jint tunFd) {
    if (hev_running) return -1;
    const char *text = (*env)->GetStringUTFChars(env, conf, NULL);
    hev_conf = strdup(text);
    (*env)->ReleaseStringUTFChars(env, conf, text);
    hev_fd = dup(tunFd);
    if (hev_fd < 0 || !hev_conf) return -2;
    if (pthread_create(&hev_thread, NULL, hev_main, NULL) != 0) {
        close(hev_fd);
        hev_fd = -1;
        return -3;
    }
    hev_running = 1;
    return 0;
}

// Stops hev and waits for its thread; its fd copy is closed
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_AetherNative_hevStop(JNIEnv *env, jclass c) {
    if (!hev_running) return;
    srpssh_hev_socks5_tunnel_quit();
    pthread_join(hev_thread, NULL);
    hev_running = 0;
    if (hev_fd >= 0) {
        close(hev_fd);
        hev_fd = -1;
    }
    free(hev_conf);
    hev_conf = NULL;
}

// --- the test connection ----------------------------------------------------------------------------------------------

static int read_full(int fd, uint8_t *buffer, size_t length) {
    size_t got = 0;
    while (got < length) {
        ssize_t n = recv(fd, buffer + got, length - got, 0);
        // the far end closed or reset it; else a timeout or an error
        if (n == 0 || (n < 0 && (errno == ECONNRESET || errno == EPIPE))) return 0;
        if (n < 0) return -1;
        got += (size_t)n;
    }
    return 1;
}

// One SOCKS5 CONNECT to 1.1.1.1:443 through 127.0.0.1:port: 1 when it went through, 0 when the far end closed the
// connection, -1 on a timeout or another error
JNIEXPORT jint JNICALL Java_tr_com_srp_vpn_AetherNative_socksProbe(JNIEnv *env, jclass c, jint port, jint timeoutSec) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval timeout = { .tv_sec = timeoutSec };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    int result = -1;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
        const uint8_t hello[3] = {0x05, 0x01, 0x00};
        const uint8_t request[10] = {0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xBB};
        uint8_t reply[10] = {0};
        ssize_t sent = send(fd, hello, sizeof(hello), MSG_NOSIGNAL);
        if (sent < 0 && (errno == EPIPE || errno == ECONNRESET)) result = 0;
        if (sent == sizeof(hello)) {
            int got = read_full(fd, reply, 2);
            if (got == 1 && reply[0] == 0x05 && reply[1] == 0x00 && send(fd, request, sizeof(request), MSG_NOSIGNAL) == sizeof(request)) {
                got = read_full(fd, reply, sizeof(reply));
                result = got == 1 ? (reply[0] == 0x05 && reply[1] == 0x00 ? 1 : -1) : got;
            } else {
                result = got == 0 ? 0 : -1;
            }
        }
    }
    close(fd);
    return result;
}

extern void srpssh_hev_socks5_tunnel_stats(size_t *tx_packets, size_t *tx_bytes, size_t *rx_packets, size_t *rx_bytes);

// hev's counters since it started: {bytes from the phone, bytes to the phone} (Expert's line)
JNIEXPORT jlongArray JNICALL Java_tr_com_srp_vpn_AetherNative_hevBytes(JNIEnv *env, jclass c) {
    size_t tx_packets = 0, tx_bytes = 0, rx_packets = 0, rx_bytes = 0;
    if (hev_running) srpssh_hev_socks5_tunnel_stats(&tx_packets, &tx_bytes, &rx_packets, &rx_bytes);
    // hev reads what the phone sends from the TUN (rx) and writes the answers to it (tx)
    jlong values[2] = {(jlong)rx_bytes, (jlong)tx_bytes};
    jlongArray result = (*env)->NewLongArray(env, 2);
    if (result) (*env)->SetLongArrayRegion(env, result, 0, 2, values);
    return result;
}
