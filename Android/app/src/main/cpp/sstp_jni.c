// The SSTP client of the iOS app on Android: the same SSTP core (sstp/) and lwIP PPP with its EAP methods, driven here by
// one engine thread per session instead of iOS's dispatch queue. It ports SSSSTPClient.m, SSFragTLSChannel.m and the PPP
// half of lwIP.m; what to do when a session ends (retry, give up, which message) stays in SstpClient.kt, like lwIP.m's
// tcpClient:didChangeState:. Kotlin hands over a connected TCP socket (direct or through a proxy) and the tunnel's fd.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "lwip/init.h"
#include "lwip/ip4_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/timeouts.h"
#include "netif/ppp/ppp_impl.h"
#include "netif/ppp/pppos.h"
#include "netif/ppp/ipcp.h"
#include "netif/ppp/eap-ttls.h"
#include "netif/ppp/srp_utf16le.h"

#include "sstp/sstp-buff.h"
#include "sstp/sstp-chap.h"
#include "sstp/sstp-common.h"
#include "sstp/sstp-fcs.h"
#include "sstp/sstp-http.h"
#include "sstp/sstp-packet.h"
#include "sstp/sstp-pppd.h"
#include "sstp/sstp-private.h"
#include "sstp/sstp-state.h"
#include "sstp/sstp-stream.h"
#include "sstp/utils.h"

enum { kEventNetworkUp = 1, kEventLinkFailure = 2, kEventSessionEnd = 3, kEventEstablished = 4, kEventProbePacket = 5 };
enum { kMaxProbeFlows = 4, kMaxProbePackets = 16 };
enum { kSendBacklogLimit = 1024 * 1024, kRecvBufferBytes = 32768, kSstpMaxRead = 16384 };
enum { kLogCapBytes = 2 * 1024 * 1024 };
enum { kEchoIntervalMs = 15000, kLwipTickMs = 200 };

// SSTPPPPState of lwIP.m
enum { kPppIdle = 0, kPppOpen = 1, kPppEstablished = 2, kPppClose = 3 };

typedef struct event {
  struct event *next;
  uint32_t generation;
  uint8_t type;
  size_t length;
  uint8_t bytes[];
} event_t;

typedef struct {
  // Settings, as SSSstp holds them on iOS
  char host[256], sni[256], username[256], password[256], anonymous[256], ttls_inner[16];
  bool pap, chap, mschap2, eap_mschapv2, peap, peap_cb, ttls, teap, identity_privacy, eap_tls13, eap_disable_legacy;
  bool allow_insecure, disable_legacy_outer, cellular;
  // MS-CHAP: hash the password byte by byte this attempt; a refusal now gets that retry (srp_utf16le.h, SstpClient.kt)
  bool mschap_bytewise, mschap_retry;
  int frag_mode, frag_first, frag_following;
  int log_level;
  char *cert_pem, *key_pem;
  int cert_pem_len, key_pem_len;

  int sock;
  int wake[2];
  atomic_bool stop;
  pthread_mutex_t tun_lock;
  pthread_cond_t tun_swapped;
  int tun, pending_tun;
  bool tun_pending;

  SSL_CTX *ctx;
  SSL *ssl;
  BIO *rbio, *wbio;
  bool handshake_done, verified;
  uint8_t leaf_sha1[20], leaf_sha256[32];
  bool have_leaf;

  uint8_t *out;
  size_t out_len, out_cap;
  bool split, burst_start;
  int first_chunk, following_chunk, gap_ms;
  long long next_write_ms;

  sstp_stream_st *stream;
  sstp_state_st *state;
  sstp_pppd_st *pppd;
  bool http_sent, sstp_started;
  char *rx;
  int rx_len;
  long long next_echo_ms;

  ppp_pcb *ppp;
  struct netif pppif;
  int ppp_state;
  u8_t last_phase;
  bool established, network_reported, link_failure_sent, closing;
  bool auth_failed;
  char connection_error[512];
  char link_failure[512];
  char sstp_reason[256];
} engine_t;

static JavaVM *jvm;
static jclass sstp_class;
static jmethodID trust_method;

static pthread_mutex_t event_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t event_ready = PTHREAD_COND_INITIALIZER;
static event_t *event_head, *event_tail;

static pthread_mutex_t engine_lock = PTHREAD_MUTEX_INITIALIZER;
static engine_t *current;
static pthread_t engine_thread;
static bool thread_running;
static uint32_t generation;
static bool lwip_ready;

// The data-plane probes of SstpClient.kt (the home screen's ping through the tunnel): packets it sends into PPP, and the
// answers of its flows, which come back as events instead of reaching the tunnel
typedef struct {
  int protocol;
  uint8_t source[4];
  uint16_t destination_port;
} probe_flow_t;

typedef struct probe_packet {
  struct probe_packet *next;
  size_t length;
  uint8_t bytes[];
} probe_packet_t;

static pthread_mutex_t probe_lock = PTHREAD_MUTEX_INITIALIZER;
static int probe_flow_count;
static probe_flow_t probe_flows[kMaxProbeFlows];
static probe_packet_t *probe_head, *probe_tail;
static int probe_queued;

static atomic_int log_fd = -1;
static atomic_int log_level;
static atomic_llong log_bytes;

static long long now_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

// srptunnel.log, in the format of ConnectionLog.kt. Level 0 lines are milestones and print at every log level.
static void slog(int level, const char *format, ...) {
  int fd = atomic_load(&log_fd);
  if (fd < 0 || level > atomic_load(&log_level)) {
    return;
  }
  char message[1200];
  va_list args;
  va_start(args, format);
  vsnprintf(message, sizeof(message), format, args);
  va_end(args);
  struct timespec real;
  clock_gettime(CLOCK_REALTIME, &real);
  struct tm local;
  localtime_r(&real.tv_sec, &local);
  char line[1300];
  int length = snprintf(line, sizeof(line), "%04d-%02d-%02d %02d:%02d:%02d.%03ld [Y] %s\n", local.tm_year + 1900,
                        local.tm_mon + 1, local.tm_mday, local.tm_hour, local.tm_min, local.tm_sec,
                        real.tv_nsec / 1000000, message);
  if (length <= 0) {
    return;
  }
  if (length > (int)sizeof(line)) {
    length = sizeof(line);
  }
  // ConnectionLog.kt trims the file when a connection starts; this only stops a runaway session from filling the disk.
  if (atomic_fetch_add(&log_bytes, length) < kLogCapBytes) {
    (void)write(fd, line, (size_t)length);
  }
}

#define LOGM(...) slog(0, __VA_ARGS__)
#define LOGI(...) slog(1, __VA_ARGS__)
#define LOGD(...) slog(2, __VA_ARGS__)

// The log gates the SSTP core and lwIP's PPP ask for (SSLog.m on iOS)
int ss_log_debug_enabled(void) { return atomic_load(&log_level) >= 2; }
int ss_log_level_value(void) { return atomic_load(&log_level); }

static void ppp_print(const char *text) { LOGI("PPP => %s", text); }
static void core_print(const char *text) { LOGD("%s", text); }

static void post_event(uint8_t type, const void *bytes, size_t length) {
  event_t *event = malloc(sizeof(*event) + length);
  if (event == NULL) {
    return;
  }
  event->next = NULL;
  event->generation = generation;
  event->type = type;
  event->length = length;
  if (length > 0) {
    memcpy(event->bytes, bytes, length);
  }
  pthread_mutex_lock(&event_lock);
  if (event_tail != NULL) {
    event_tail->next = event;
  } else {
    event_head = event;
  }
  event_tail = event;
  pthread_cond_signal(&event_ready);
  pthread_mutex_unlock(&event_lock);
}

// Several NUL-terminated strings in one payload
static void post_strings(uint8_t type, const char *const *texts, int count) {
  size_t length = 0;
  for (int i = 0; i < count; i++) {
    length += strlen(texts[i]) + 1;
  }
  char *payload = malloc(length > 0 ? length : 1);
  if (payload == NULL) {
    return;
  }
  size_t offset = 0;
  for (int i = 0; i < count; i++) {
    size_t size = strlen(texts[i]) + 1;
    memcpy(payload + offset, texts[i], size);
    offset += size;
  }
  post_event(type, payload, length);
  free(payload);
}

static void wake(engine_t *e) {
  char byte = 1;
  (void)write(e->wake[1], &byte, 1);
}

#pragma mark - outer TLS

static bool out_append(engine_t *e, const uint8_t *bytes, size_t length) {
  if (e->out_len + length > e->out_cap) {
    size_t capacity = e->out_cap ? e->out_cap : 65536;
    while (capacity < e->out_len + length) {
      capacity *= 2;
    }
    uint8_t *grown = realloc(e->out, capacity);
    if (grown == NULL) {
      return false;
    }
    e->out = grown;
    e->out_cap = capacity;
  }
  memcpy(e->out + e->out_len, bytes, length);
  e->out_len += length;
  return true;
}

// TLS bytes the engine produced go to the socket queue; SSFragTLSChannel's drainWriteBio splits them when they are written
static void drain_wbio(engine_t *e) {
  uint8_t buffer[16384];
  int read;
  while ((read = BIO_read(e->wbio, buffer, sizeof(buffer))) > 0) {
    out_append(e, buffer, (size_t)read);
  }
}

static void session_fail(engine_t *e, const char *format, ...) {
  if (e->connection_error[0] == '\0') {
    va_list args;
    va_start(args, format);
    vsnprintf(e->connection_error, sizeof(e->connection_error), format, args);
    va_end(args);
  }
  atomic_store(&e->stop, true);
}

// Writes what the socket takes now. During the handshake with TLS Fragmentation each write is one chunk, first the first
// chunk of a burst and then following chunks, with a gap between them in Auto mode, so TCP sends them as separate segments.
static void flush_out(engine_t *e) {
  while (e->out_len > 0) {
    size_t length = e->out_len;
    if (e->split) {
      if (e->gap_ms > 0 && now_ms() < e->next_write_ms) {
        return;
      }
      size_t chunk = (size_t)(e->burst_start ? e->first_chunk : e->following_chunk);
      if (length > chunk) {
        length = chunk;
      }
    }
    ssize_t sent = send(e->sock, e->out, length, MSG_NOSIGNAL);
    if (sent < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        return;
      }
      session_fail(e, "The connection to the server was lost (%s).", strerror(errno));
      return;
    }
    memmove(e->out, e->out + sent, e->out_len - (size_t)sent);
    e->out_len -= (size_t)sent;
    if (e->split) {
      e->burst_start = false;
      if (e->gap_ms > 0) {
        e->next_write_ms = now_ms() + e->gap_ms;
      }
    }
  }
  if (e->split) {
    e->burst_start = true;   // the next burst starts with the first chunk again
  }
}

static bool is_ip_literal(const char *text) {
  struct in6_addr address;
  return inet_pton(AF_INET, text, &address) == 1 || inet_pton(AF_INET6, text, &address) == 1;
}

// Chain trust through the platform's trust manager (SecTrust on iOS), from the engine thread.
static bool platform_trusts(STACK_OF(X509) *chain, X509 *leaf, char *reason, size_t reason_size) {
  JNIEnv *env = NULL;
  if (jvm == NULL || (*jvm)->GetEnv(jvm, (void **)&env, JNI_VERSION_1_6) != JNI_OK || env == NULL) {
    snprintf(reason, reason_size, "the certificate could not be evaluated");
    return false;
  }
  int count = chain != NULL ? sk_X509_num(chain) : 0;
  bool leaf_in_chain = count > 0 && X509_cmp(sk_X509_value(chain, 0), leaf) == 0;
  int total = count + (leaf_in_chain ? 0 : 1);
  jclass byte_array = (*env)->FindClass(env, "[B");
  jobjectArray array = (*env)->NewObjectArray(env, total, byte_array, NULL);
  int index = 0;
  for (int i = -1; i < count; i++) {
    X509 *certificate = i < 0 ? (leaf_in_chain ? NULL : leaf) : sk_X509_value(chain, i);
    if (certificate == NULL) {
      continue;
    }
    unsigned char *der = NULL;
    int length = i2d_X509(certificate, &der);
    if (length > 0) {
      jbyteArray bytes = (*env)->NewByteArray(env, length);
      (*env)->SetByteArrayRegion(env, bytes, 0, length, (const jbyte *)der);
      (*env)->SetObjectArrayElement(env, array, index++, bytes);
      (*env)->DeleteLocalRef(env, bytes);
    }
    OPENSSL_free(der);
  }
  jstring answer = (jstring)(*env)->CallStaticObjectMethod(env, sstp_class, trust_method, array);
  (*env)->DeleteLocalRef(env, array);
  (*env)->DeleteLocalRef(env, byte_array);
  if ((*env)->ExceptionCheck(env)) {
    (*env)->ExceptionClear(env);
    snprintf(reason, reason_size, "the certificate could not be evaluated");
    return false;
  }
  if (answer == NULL) {
    return true;
  }
  const char *text = (*env)->GetStringUTFChars(env, answer, NULL);
  snprintf(reason, reason_size, "%s", text != NULL ? text : "not trusted");
  if (text != NULL) {
    (*env)->ReleaseStringUTFChars(env, answer, text);
  }
  (*env)->DeleteLocalRef(env, answer);
  return false;
}

// An EAP server on another host than the SSTP server (RRAS relaying to RADIUS) shows its own certificate; like the outer
// TLS, it must chain to a root the device trusts (srp_eap_cert_trusted in lwIP.m)
static int eap_cert_trusted(const u_char *const *ders, const int *lens, int count, char *reason, int reason_len) {
  STACK_OF(X509) *chain = sk_X509_new_null();
  X509 *leaf = NULL;
  for (int i = 0; i < count; i++) {
    const unsigned char *bytes = ders[i];
    X509 *certificate = d2i_X509(NULL, &bytes, lens[i]);
    if (certificate == NULL) {
      continue;
    }
    if (leaf == NULL) {
      leaf = certificate;
    }
    sk_X509_push(chain, certificate);
  }
  int trusted = 0;
  if (leaf == NULL) {
    snprintf(reason, (size_t)reason_len, "its certificate could not be read");
  } else {
    trusted = platform_trusts(chain, leaf, reason, (size_t)reason_len) ? 1 : 0;
  }
  sk_X509_pop_free(chain, X509_free);
  return trusted;
}

static bool verify_peer(engine_t *e) {
  X509 *leaf = SSL_get1_peer_certificate(e->ssl);
  if (leaf == NULL) {
    session_fail(e, "The server did not present a certificate.");
    return false;
  }
  unsigned char *der = NULL;
  int length = i2d_X509(leaf, &der);
  if (length > 0) {
    SHA1(der, (size_t)length, e->leaf_sha1);
    SHA256(der, (size_t)length, e->leaf_sha256);
    e->have_leaf = true;
  }
  OPENSSL_free(der);
  bool ok = true;
  if (!e->allow_insecure) {
    // The name the certificate must carry: the Custom SNI when it is on, else the Server field
    char reason[400] = "";
    int matches = is_ip_literal(e->sni) ? X509_check_ip_asc(leaf, e->sni, 0) : X509_check_host(leaf, e->sni, 0, 0, NULL);
    if (matches != 1) {
      snprintf(reason, sizeof(reason), "it is not valid for %s", e->sni);
      ok = false;
    } else {
      ok = platform_trusts(SSL_get_peer_cert_chain(e->ssl), leaf, reason, sizeof(reason));
    }
    if (!ok) {
      session_fail(e, "The server certificate is not trusted: %s", reason);
    }
  }
  X509_free(leaf);
  return ok;
}

static void send_http_hello(engine_t *e);

static void pump_handshake(engine_t *e) {
  int result = SSL_do_handshake(e->ssl);
  drain_wbio(e);
  if (result == 1) {
    e->handshake_done = true;
    e->split = false;   // handshake only: plain pass-through from here
    LOGM("TLS: handshake complete (%s)", SSL_get_version(e->ssl));
    if (verify_peer(e)) {
      e->verified = true;
      send_http_hello(e);
    }
    return;
  }
  int code = SSL_get_error(e->ssl, result);
  if (code == SSL_ERROR_WANT_READ || code == SSL_ERROR_WANT_WRITE) {
    return;
  }
  char error[256];
  ERR_error_string_n(ERR_get_error(), error, sizeof(error));
  session_fail(e, "TLS handshake failed: %s", error);
}

static void tls_send(engine_t *e, const uint8_t *bytes, size_t length) {
  while (length > 0) {
    int written = SSL_write(e->ssl, bytes, (int)length);
    if (written > 0) {
      bytes += written;
      length -= (size_t)written;
      drain_wbio(e);
      continue;
    }
    int code = SSL_get_error(e->ssl, written);
    if (code == SSL_ERROR_WANT_WRITE || code == SSL_ERROR_WANT_READ) {
      drain_wbio(e);
      continue;
    }
    LOGI("TLS: SSL_write failed (%d)", code);
    session_fail(e, "The connection to the server was lost.");
    return;
  }
}

#pragma mark - SSTP (SSSSTPClient.m)

static void handle_plaintext(engine_t *e, const uint8_t *bytes, int length);

static status_t sstp_send(sstp_stream_st *stream, sstp_buff_st *tx, sstp_complete_fn complete, void *ctx, int timeout) {
  (void)timeout;
  engine_t *e = stream->ctx;
  if (atomic_load(&e->stop) || !e->verified) {
    return SSTP_FAIL;
  }
  tls_send(e, (const uint8_t *)tx->data + tx->off, (size_t)(tx->len - tx->off));
  complete(stream, tx, ctx, SSTP_OKAY);
  return SSTP_OKAY;
}

static status_t sstp_cert_hash(sstp_stream_st *stream, int proto, unsigned char *hash, int hlen) {
  engine_t *e = stream->ctx;
  if (!e->have_leaf) {
    return SSTP_FAIL;
  }
  if (proto & SSTP_PROTO_HASH_SHA256) {
    memcpy(hash, e->leaf_sha256, hlen < 32 ? (size_t)hlen : 32);
  } else {
    memcpy(hash, e->leaf_sha1, hlen < 20 ? (size_t)hlen : 20);
  }
  return SSTP_OKAY;
}

static bool matches_probe_flow(const uint8_t *packet, size_t length) {
  if (length < 28 || (packet[0] >> 4) != 4) {
    return false;
  }
  size_t ihl = (size_t)(packet[0] & 0x0f) * 4;
  if (ihl < 20 || length < ihl + 4) {
    return false;
  }
  uint16_t destination_port = (uint16_t)((packet[ihl + 2] << 8) | packet[ihl + 3]);
  bool found = false;
  pthread_mutex_lock(&probe_lock);
  for (int i = 0; i < probe_flow_count && !found; i++) {
    found = probe_flows[i].protocol == packet[9] && memcmp(probe_flows[i].source, packet + 12, 4) == 0 &&
            probe_flows[i].destination_port == destination_port;
  }
  pthread_mutex_unlock(&probe_lock);
  return found;
}

static void tun_write(engine_t *e, const uint8_t *packet, size_t length) {
  if (matches_probe_flow(packet, length)) {
    post_event(kEventProbePacket, packet, length);
    return;
  }
  if (e->tun < 0) {
    return;
  }
  // A full tunnel queue drops the packet, as a network would; TCP sends it again
  (void)write(e->tun, packet, length);
}

static status_t sstp_forward(void *arg, uint8_t *buf, int len) {
  engine_t *e = arg;
  if (len < 4) {
    return SSTP_FAIL;
  }
  uint16_t protocol = (uint16_t)((buf[2] << 8) | buf[3]);
  if (protocol == 0x21) {
    // IPv4 goes straight to the tunnel; lwIP only sees PPP's own protocols
    if (len >= 24) {
      size_t total = ((size_t)buf[6] << 8) | buf[7];
      if (total > (size_t)(len - 4)) {
        total = (size_t)(len - 4);
      }
      tun_write(e, buf + 4, total);
    }
    return SSTP_OKAY;
  }
  int frame_length = (len << 1) + 4;
  uint8_t *frame = malloc((size_t)frame_length);
  if (frame == NULL) {
    return SSTP_FAIL;
  }
  if (sstp_frame_encode(buf, len, frame, &frame_length) == SSTP_OKAY && e->ppp != NULL) {
    pppos_input(e->ppp, frame, frame_length);
  }
  free(frame);
  return SSTP_OKAY;
}

static void ppp_begin(engine_t *e);

static status_t sstp_state_changed(void *arg, sstp_state_t state) {
  engine_t *e = arg;
  switch (state) {
    case SSTP_CALL_CONNECT:
      LOGI("Started PPP Link Negotiation");
      ppp_begin(e);
      sstp_state_set_forward(e->state, sstp_forward, e);
      break;
    case SSTP_CALL_ESTABLISHED:
      LOGM("PPP Link Negotiation ESTABLISHED");
      e->next_echo_ms = now_ms() + kEchoIntervalMs;
      e->ppp_state = kPppEstablished;
      if (!e->established) {
        e->established = true;
        post_event(kEventEstablished, NULL, 0);
      }
      break;
    default: {
      const char *reason = sstp_state_reason(e->state);
      LOGM("Connection was aborted, state:%d, reason:%s", (int)state, reason != NULL ? reason : "");
      snprintf(e->sstp_reason, sizeof(e->sstp_reason), "%s", reason != NULL ? reason : "");
      e->ppp_state = kPppClose;
      // The server ended the SSTP call (Call Disconnect or Abort). Some keep the TCP connection open afterwards, as
      // SoftEther does when it accepts none of the profile's authentication methods, so the session ends here
      atomic_store(&e->stop, true);
      break;
    }
  }
  return SSTP_OKAY;
}

static void sstp_pppd_event(void *arg, sstp_pppd_event_t event) {
  engine_t *e = arg;
  switch (event) {
    case SSTP_PPP_UP:
      if (sstp_state_accept(e->state) == SSTP_FAIL) {
        LOGM("Negotiation with server failure");
      }
      break;
    case SSTP_PPP_AUTH: {
      uint8_t send_key[16], receive_key[16];
      if (sstp_chap_mppe_get(sstp_pppd_getchap(e->pppd), e->password, send_key, receive_key, 0) == SSTP_FAIL) {
        LOGM("Negotiation auth chap mppe get failure");
        return;
      }
      sstp_state_mppe_keys(e->state, send_key, receive_key, 16);
      break;
    }
    case SSTP_PPP_START:
      sstp_state_resume_recv(e->state);
      break;
    default:
      LOGI("Receive pppd event: %d", (int)event);
      break;
  }
}

static void send_http_hello(engine_t *e) {
  char uuid[40];
  uint8_t random[16];
  FILE *source = fopen("/dev/urandom", "rb");
  if (source == NULL || fread(random, 1, sizeof(random), source) != sizeof(random)) {
    for (size_t i = 0; i < sizeof(random); i++) {
      random[i] = (uint8_t)(now_ms() >> (i % 8));
    }
  }
  if (source != NULL) {
    fclose(source);
  }
  random[6] = (uint8_t)((random[6] & 0x0f) | 0x40);
  random[8] = (uint8_t)((random[8] & 0x3f) | 0x80);
  snprintf(uuid, sizeof(uuid), "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X", random[0],
           random[1], random[2], random[3], random[4], random[5], random[6], random[7], random[8], random[9], random[10],
           random[11], random[12], random[13], random[14], random[15]);
  LOGI("Client Unique ID: %s", uuid);
  char request[600];
  int length = snprintf(request, sizeof(request),
                        "SSTP_DUPLEX_POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %llu\r\nSSTPCORRELATIONID: %s\r\n\r\n",
                        SSTP_HTTP_DFLT_PATH, e->host, -1ULL, uuid);
  tls_send(e, (const uint8_t *)request, (size_t)length);
  e->http_sent = true;
}

// Whole SSTP packets out of the decrypted stream (didReceiveMessage32768 in SSSSTPClient.m)
static void handle_plaintext(engine_t *e, const uint8_t *bytes, int length) {
  while (length > 0) {
    int take = length;
    if (take > kRecvBufferBytes - 1 - e->rx_len) {
      take = kRecvBufferBytes - 1 - e->rx_len;
    }
    if (take <= 0) {
      session_fail(e, "The server sent a packet larger than SSTP allows.");
      return;
    }
    memcpy(e->rx + e->rx_len, bytes, (size_t)take);
    e->rx_len += take;
    e->rx[e->rx_len] = '\0';
    bytes += take;
    length -= take;
    if (!e->sstp_started) {
      // The HTTP response completes the handshake first
      if (sstp_recv_http_hello_complete(e->stream, e->rx, SSTP_OKAY) != SSTP_OKAY) {
        continue;
      }
      e->sstp_started = true;
      e->rx_len = 0;
      sstp_state_start(e->state);
      continue;
    }
    while (e->rx_len > 4 && !atomic_load(&e->stop)) {
      sstp_pkt_st *packet = (sstp_pkt_st *)e->rx;
      int packet_length = ntohs(packet->length) & 0x0fff;
      if (packet_length < 4) {
        session_fail(e, "The server sent an invalid SSTP packet.");
        return;
      }
      if (e->rx_len < packet_length) {
        break;
      }
      sstp_state_read_msg(e->state, e->stream, e->rx, packet_length);
      memmove(e->rx, e->rx + packet_length, (size_t)(e->rx_len - packet_length));
      e->rx_len -= packet_length;
    }
  }
}

static void drain_ssl_read(engine_t *e) {
  uint8_t buffer[kSstpMaxRead];
  while (!atomic_load(&e->stop)) {
    int read = SSL_read(e->ssl, buffer, sizeof(buffer));
    if (read > 0) {
      handle_plaintext(e, buffer, read);
      continue;
    }
    int code = SSL_get_error(e->ssl, read);
    if (code == SSL_ERROR_WANT_READ) {
      return;
    }
    if (code == SSL_ERROR_ZERO_RETURN || code == SSL_ERROR_SYSCALL) {
      session_fail(e, "The server closed the connection.");
      return;
    }
    char error[256];
    ERR_error_string_n(ERR_get_error(), error, sizeof(error));
    session_fail(e, "The connection to the server failed: %s", error);
    return;
  }
}

#pragma mark - PPP (lwIP.m)

static bool tls13_refused(ppp_pcb *pcb) {
  return pcb != NULL && pcb->settings.eap_tls13_enabled && pcb->settings.eap_tls_hs_started &&
         !pcb->settings.eap_tls_hs_done;
}

// With Identity Privacy the server sees "anonymous" until the tunnel is up, and a server that checks that outer identity
// (as RRAS does with local accounts) refuses it
static const char *authentication_failure(ppp_pcb *pcb) {
  if (pcb != NULL && pcb->settings.eap_tls_cert_pem != NULL) {
    return "Authentication failed. The server rejected the client certificate; check that the server trusts its issuer "
           "and that it is still valid.";
  }
  if (pcb != NULL && pcb->settings.eap_identity_privacy) {
    return "Authentication failed. The server rejected the username or password, or the anonymous outer identity of "
           "Identity Privacy; if it checks the outer identity, turn Identity Privacy off.";
  }
  return "Authentication failed. The server rejected the username or password.";
}

static void certificate_refusal(ppp_pcb *pcb, char *text, size_t size) {
  text[0] = '\0';
  if (pcb != NULL && pcb->settings.eap_cert_rejected[0] != '\0') {
    snprintf(text, size,
             "The EAP server's certificate is not trusted: %s. Install its root certificate on the device, or turn on "
             "Allow Untrusted Certificate in the profile.",
             pcb->settings.eap_cert_rejected);
  }
}

static void link_status(ppp_pcb *pcb, int err_code, void *ctx) {
  engine_t *e = ctx;
  if (err_code == PPPERR_NONE) {
    LOGI("ppp_link_status_cb: PPPERR_NONE, our_ip4addr = %s", ip4addr_ntoa(netif_ip4_addr(ppp_netif(pcb))));
    return;
  }
  static const char *names[] = {"PPPERR_NONE", "PPPERR_PARAM", "PPPERR_OPEN", "PPPERR_DEVICE", "PPPERR_ALLOC", "PPPERR_USER",
                                "PPPERR_CONNECT", "PPPERR_AUTHFAIL", "PPPERR_PROTOCOL", "PPPERR_PEERDEAD", "PPPERR_IDLETIMEOUT",
                                "PPPERR_CONNECTTIME", "PPPERR_LOOPBACK"};
  if (err_code > 0 && err_code < (int)(sizeof(names) / sizeof(names[0]))) {
    LOGM("ppp_link_status_cb: %s", names[err_code]);
  } else {
    LOGM("ppp_link_status_cb: unknown errCode %d", err_code);
  }
  if (e->closing) {
    return;
  }
  // Negotiation failures go to the UI before the link is up; an authentication failure must not start the reconnect loop
  char reason[600] = "";
  switch (err_code) {
    case PPPERR_AUTHFAIL:
      if (tls13_refused(pcb)) {
        break;   // not the credentials: the disconnect that follows retries with TLS 1.2
      }
      certificate_refusal(pcb, reason, sizeof(reason));
      if (reason[0] == '\0' && e->mschap_retry) {
        break;   // the disconnect that follows retries with the password hashed byte by byte
      }
      e->auth_failed = true;
      if (reason[0] == '\0') {
        snprintf(reason, sizeof(reason), "%s", authentication_failure(pcb));
      }
      break;
    case PPPERR_CONNECT:
      snprintf(reason, sizeof(reason), "Connection lost during PPP negotiation.");
      break;
    case PPPERR_PEERDEAD:
      snprintf(reason, sizeof(reason), "Server stopped responding.");
      break;
    default:
      break;
  }
  if (reason[0] != '\0' && e->ppp_state != kPppEstablished && !e->link_failure_sent) {
    e->link_failure_sent = true;
    snprintf(e->link_failure, sizeof(e->link_failure), "%s", reason);
    const char *texts[] = {reason};
    post_strings(kEventLinkFailure, texts, 1);
  }
}

static void ip_text(uint32_t address, char *text, size_t size) {
  ip4_addr_t value;
  value.addr = address;
  ip4addr_ntoa_r(&value, text, (int)size);
}

static void phase_changed(ppp_pcb *pcb, u8_t phase, void *ctx) {
  engine_t *e = ctx;
  // The message about a server that ended PPP names the furthest phase the link reached; termination passes through
  // ESTABLISH again, which must not count
  if (phase >= PPP_PHASE_ESTABLISH && phase <= PPP_PHASE_RUNNING && phase > e->last_phase) {
    e->last_phase = phase;
  }
  static const char *names[] = {"DEAD", "MASTER", "HOLDOFF", "INITIALIZE", "SERIALCONN", "DORMANT", "ESTABLISH",
                                "AUTHENTICATE", "CALLBACK", "NETWORK", "RUNNING", "TERMINATE", "DISCONNECT"};
  LOGI("phase: %s", phase < sizeof(names) / sizeof(names[0]) ? names[phase] : "DISCONNECT");
  if (phase == PPP_PHASE_NETWORK && pcb->settings.eap_mppe_keys_ok) {
    // Tunneled EAP (PEAP/TTLS/TEAP): the engine derived the MPPE session keys; feed them to the SSTP Call Connected
    // crypto binding before the first IPCP frame triggers it
    sstp_state_mppe_keys(e->state, pcb->settings.eap_mppe_send_key, pcb->settings.eap_mppe_recv_key, 32);
    // The cleartext snoop never fires for tunneled EAP; mark auth done so the first outbound IPCP frame triggers the
    // Connected message
    sstp_pppd_auth_done(e->pppd);
    LOGM("MPPE keys for the SSTP crypto binding set from the tunneled EAP session");
  }
  if (phase == PPP_PHASE_RUNNING && !e->network_reported) {
    e->network_reported = true;
    char ours[32] = "", peer[32] = "1.0.0.1", dns1[32] = "1.1.1.1", dns2[32] = "";
    ip_text(pcb->ipcp_wantoptions.ouraddr, ours, sizeof(ours));
    if (pcb->ipcp_hisoptions.hisaddr != 0) {
      ip_text(pcb->ipcp_hisoptions.hisaddr, peer, sizeof(peer));
    }
    if (pcb->ipcp_gotoptions.dnsaddr[0] != 0) {
      ip_text(pcb->ipcp_gotoptions.dnsaddr[0], dns1, sizeof(dns1));
    }
    if (pcb->ipcp_gotoptions.dnsaddr[1] != 0) {
      ip_text(pcb->ipcp_gotoptions.dnsaddr[1], dns2, sizeof(dns2));
    }
    LOGI("createNetworkSetting DNS: %s %s, IP: %s, remote: %s", dns1, dns2, ours, peer);
    const char *texts[] = {ours, peer, dns1, dns2};
    post_strings(kEventNetworkUp, texts, 4);
  }
}

static u32_t ppp_output(ppp_pcb *pcb, u8_t *data, u32_t len, void *ctx) {
  (void)pcb;
  engine_t *e = ctx;
  if (!atomic_load(&e->stop)) {
    sstp_pppd_recv(e->pppd, (char *)data, (int)len);
  }
  return len;
}

static void ppp_begin(engine_t *e) {
  e->ppp = pppos_create(&e->pppif, ppp_output, link_status, e);
  if (e->ppp == NULL) {
    session_fail(e, "PPP could not start.");
    return;
  }
  ppp_set_notify_phase_callback(e->ppp, phase_changed);
  u8_t types = 0;
  if (e->pap) types |= PPPAUTHTYPE_PAP;
  if (e->chap) types |= PPPAUTHTYPE_CHAP;
  if (e->mschap2) types |= PPPAUTHTYPE_MSCHAP_V2;
  if (e->eap_mschapv2 || e->peap || e->ttls || e->teap || e->cert_pem != NULL) types |= PPPAUTHTYPE_EAP;
  // Never the credentials
  LOGI("PPP auth: PAP %s, CHAP %s, MSCHAPv2 %s, EAP-MSCHAPv2 %s, PEAP %s, TTLS %s, TEAP %s",
       e->pap ? "enabled" : "disabled", e->chap ? "enabled" : "disabled", e->mschap2 ? "enabled" : "disabled",
       e->eap_mschapv2 ? "enabled" : "disabled", e->peap ? "enabled" : "disabled", e->ttls ? "enabled" : "disabled",
       e->teap ? "enabled" : "disabled");
  srp_mschap_bytewise_password = e->mschap_bytewise ? 1 : 0;   // read by this attempt's MS-CHAP and crypto binding
  ppp_set_auth(e->ppp, types, e->username, e->password);
  ppp_set_usepeerdns(e->ppp, true);
  ppp_settings *settings = &e->ppp->settings;
  settings->eap_mschapv2_enable = e->eap_mschapv2 ? 1 : 0;
  settings->eap_peap_enable = e->peap ? 1 : 0;
  settings->peap_require_cb = e->peap_cb ? 1 : 0;
  settings->eap_ttls_enable = e->ttls ? 1 : 0;
  // TTLS inner method: "eap" = inner EAP-MSCHAPv2 via EAP-Message AVPs; "pap"/"chap" = AVP-based (RFC 5281 11.2)
  settings->eap_ttls_inner = EAP_TTLS_INNER_EAP;
  if (strcmp(e->ttls_inner, "pap") == 0) {
    settings->eap_ttls_inner = EAP_TTLS_INNER_PAP;
  } else if (strcmp(e->ttls_inner, "chap") == 0) {
    settings->eap_ttls_inner = EAP_TTLS_INNER_CHAP;
  }
  settings->eap_teap_enable = e->teap ? 1 : 0;
  settings->eap_tls_cert_pem = (const u_char *)e->cert_pem;
  settings->eap_tls_cert_pem_len = e->cert_pem_len;
  settings->eap_tls_key_pem = (const u_char *)e->key_pem;
  settings->eap_tls_key_pem_len = e->key_pem_len;
  if (e->peap || e->ttls || e->teap || e->cert_pem != NULL) {
    // PEAP/TTLS need many more EAP requests than the default budget of 10: TLS fragment acks + inner identity +
    // capabilities + inner MSCHAPv2 easily exceed it
    settings->eap_allow_req = 40;
  }
  settings->eap_identity_privacy = e->identity_privacy ? 1 : 0;
  settings->eap_anonymous_identity = e->anonymous[0] != '\0' ? e->anonymous : "anonymous";
  settings->eap_tls13_enabled = e->eap_tls13 ? 1 : 0;
  settings->eap_tls_hs_started = 0;
  settings->eap_tls_hs_done = 0;
  settings->eap_disable_legacy_tls = e->eap_disable_legacy ? 1 : 0;
  settings->peap_cert_check = e->allow_insecure ? 0 : 1;
  settings->eap_cert_trust = eap_cert_trusted;
  settings->eap_cert_rejected[0] = '\0';
  if (settings->peap_cert_check) {
    // Pin the inner TLS certificate to the outer connection's leaf certificate: RRAS/NPS normally presents the same
    // certificate inside PEAP; another one must chain to a trusted root (eap_cert_trust)
    if (e->have_leaf) {
      memcpy(settings->peap_cert_sha256, e->leaf_sha256, 32);
    } else {
      LOGI("PPP: no outer certificate hash available, inner cert check will fail closed");
      memset(settings->peap_cert_sha256, 0, 32);
    }
  }
  e->last_phase = PPP_PHASE_DEAD;
  e->ppp_state = kPppOpen;
  ppp_connect(e->ppp, 0);
}

static void ppp_end(engine_t *e) {
  if (e->ppp == NULL) {
    return;
  }
  e->closing = true;
  netif_remove(&e->pppif);
  ppp_close(e->ppp, 1);
  ppp_free(e->ppp);
  e->ppp = NULL;
}

static void ppp_send_ipv4(engine_t *e, const uint8_t *packet, size_t length) {
  struct pbuf *buffer = pbuf_alloc(PBUF_RAW, (u16_t)length, PBUF_POOL);
  if (buffer == NULL) {
    return;
  }
  pbuf_take(buffer, packet, (u16_t)length);
  ip4_addr_t destination;
  memcpy(&destination.addr, packet + 16, 4);
  e->pppif.output(&e->pppif, buffer, &destination);
  pbuf_free(buffer);
}

static void send_probes(engine_t *e) {
  pthread_mutex_lock(&probe_lock);
  probe_packet_t *list = probe_head;
  probe_head = probe_tail = NULL;
  probe_queued = 0;
  pthread_mutex_unlock(&probe_lock);
  while (list != NULL) {
    probe_packet_t *next = list->next;
    if (e->ppp_state == kPppEstablished && e->ppp != NULL) {
      ppp_send_ipv4(e, list->bytes, list->length);
    }
    free(list);
    list = next;
  }
}

// Device packets into PPP once the call is up (WriteIPPacketInQueue in lwIP.m)
static void tun_read(engine_t *e) {
  uint8_t packet[2048];
  for (int i = 0; i < 64 && e->out_len < kSendBacklogLimit && !atomic_load(&e->stop); i++) {
    ssize_t length = read(e->tun, packet, sizeof(packet));
    if (length <= 0) {
      return;
    }
    if (length < 20 || (packet[0] >> 4) != 4 || e->ppp_state != kPppEstablished || e->ppp == NULL) {
      continue;
    }
    ppp_send_ipv4(e, packet, (size_t)length);
  }
}

#pragma mark - engine thread

static void engine_free(engine_t *e) {
  if (e->state != NULL) sstp_state_free(e->state);
  if (e->pppd != NULL) sstp_pppd_free(e->pppd);
  if (e->stream != NULL) sstp_stream_destroy(e->stream);
  if (e->ssl != NULL) SSL_free(e->ssl);
  if (e->ctx != NULL) SSL_CTX_free(e->ctx);
  if (e->sock >= 0) close(e->sock);
  if (e->wake[0] >= 0) close(e->wake[0]);
  if (e->wake[1] >= 0) close(e->wake[1]);
  if (e->cert_pem != NULL) {
    OPENSSL_cleanse(e->cert_pem, (size_t)e->cert_pem_len);
    free(e->cert_pem);
  }
  if (e->key_pem != NULL) {
    OPENSSL_cleanse(e->key_pem, (size_t)e->key_pem_len);
    free(e->key_pem);
  }
  OPENSSL_cleanse(e->password, sizeof(e->password));
  pthread_mutex_destroy(&e->tun_lock);
  pthread_cond_destroy(&e->tun_swapped);
  free(e->rx);
  free(e->out);
  free(e);
}

static void report_end(engine_t *e) {
  // The facts SstpClient.kt needs for lwIP.m's decision: was the call up, did PPP start and how far it got, what failed
  // A server whose authentication protocol the profile refused can still let LCP open; the link then passes the
  // authentication phase without authenticating, and the close that follows is about the methods, not addresses
  int phase = e->last_phase;
  if (e->ppp != NULL && phase >= PPP_PHASE_NETWORK && !e->ppp->lcp_hisoptions.neg_upap && !e->ppp->lcp_hisoptions.neg_chap &&
      !e->ppp->lcp_hisoptions.neg_eap) {
    phase = PPP_PHASE_ESTABLISH;
  }
  char flags[8];
  snprintf(flags, sizeof(flags), "%c%c%c%c%d", e->established ? '1' : '0', e->ppp != NULL ? '1' : '0',
           e->auth_failed || (e->ppp != NULL && e->ppp->err_code == PPPERR_AUTHFAIL) ? '1' : '0',
           tls13_refused(e->ppp) ? '1' : '0', phase);
  char refusal[600] = "";
  certificate_refusal(e->ppp, refusal, sizeof(refusal));
  const char *auth = e->ppp != NULL ? authentication_failure(e->ppp) : "";
  const char *texts[] = {flags, e->connection_error, e->link_failure, refusal, auth, e->sstp_reason};
  post_strings(kEventSessionEnd, texts, 6);
}

static void *engine_main(void *arg) {
  engine_t *e = arg;
  JNIEnv *env = NULL;
  if (jvm != NULL) {
    (*jvm)->AttachCurrentThread(jvm, &env, NULL);
  }
  if (!lwip_ready) {
    lwip_init();
    ppp_set_print_func(ppp_print);
    x_set_print_func(core_print);
    lwip_ready = true;
  }
  sys_restart_timeouts();
  e->ctx = SSL_CTX_new(TLS_client_method());
  if (e->ctx != NULL && e->disable_legacy_outer) {
    SSL_CTX_set_min_proto_version(e->ctx, TLS1_2_VERSION);
  }
  e->ssl = e->ctx != NULL ? SSL_new(e->ctx) : NULL;
  if (e->ssl == NULL) {
    session_fail(e, "TLS could not start.");
  } else {
    SSL_set_verify(e->ssl, SSL_VERIFY_NONE, NULL);   // the platform evaluates trust after the handshake
    if (!is_ip_literal(e->sni)) {
      SSL_set_tlsext_host_name(e->ssl, e->sni);
    }
    e->rbio = BIO_new(BIO_s_mem());
    e->wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(e->ssl, e->rbio, e->wbio);
    SSL_set_connect_state(e->ssl);
    LOGI("Connecting to: %s", e->host);
    LOGI("TLS SNI: %s", e->sni);
    LOGI("Certificate verification hostname: %s", e->sni);
    if (e->split) {
      LOGM("TLS-frag: mode=%s (first=%d following=%d gap=%d ms)", e->frag_mode == 1 ? "auto" : "manual", e->first_chunk,
           e->following_chunk, e->gap_ms);
    }
    pump_handshake(e);
  }
  long long next_tick = now_ms() + kLwipTickMs;
  while (!atomic_load(&e->stop)) {
    flush_out(e);
    pthread_mutex_lock(&e->tun_lock);
    if (e->tun_pending) {
      e->tun = e->pending_tun;
      e->tun_pending = false;
      pthread_cond_broadcast(&e->tun_swapped);
    }
    pthread_mutex_unlock(&e->tun_lock);
    struct pollfd fds[3];
    int count = 0;
    fds[count++] = (struct pollfd){.fd = e->wake[0], .events = POLLIN};
    fds[count++] = (struct pollfd){.fd = e->sock, .events = (short)(POLLIN | (e->out_len > 0 ? POLLOUT : 0))};
    bool reading_tun = e->tun >= 0 && e->ppp_state == kPppEstablished && e->out_len < kSendBacklogLimit;
    if (reading_tun) {
      fds[count++] = (struct pollfd){.fd = e->tun, .events = POLLIN};
    }
    long long now = now_ms();
    long long deadline = next_tick;
    if (e->ppp_state == kPppEstablished && e->next_echo_ms < deadline) deadline = e->next_echo_ms;
    if (e->split && e->out_len > 0 && e->next_write_ms > now && e->next_write_ms < deadline) deadline = e->next_write_ms;
    int timeout = deadline > now ? (int)(deadline - now) : 0;
    int ready = poll(fds, (nfds_t)count, timeout);
    if (ready < 0 && errno != EINTR) {
      session_fail(e, "The connection failed (%s).", strerror(errno));
      break;
    }
    if (fds[0].revents & POLLIN) {
      char drain[64];
      while (read(e->wake[0], drain, sizeof(drain)) > 0) {
      }
    }
    if (fds[1].revents & (POLLIN | POLLERR | POLLHUP)) {
      uint8_t buffer[65536];
      ssize_t received = recv(e->sock, buffer, sizeof(buffer), 0);
      if (received > 0) {
        BIO_write(e->rbio, buffer, (int)received);
        if (!e->handshake_done) {
          pump_handshake(e);
        } else {
          drain_ssl_read(e);
        }
      } else if (received == 0) {
        session_fail(e, e->handshake_done ? "The server closed the connection." :
                        "The connection closed during the TLS handshake.");
      } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        session_fail(e, "The connection to the server was lost (%s).", strerror(errno));
      }
    }
    if (reading_tun && count > 2 && (fds[2].revents & POLLIN)) {
      tun_read(e);
    }
    send_probes(e);
    now = now_ms();
    if (now >= next_tick) {
      sys_check_timeouts();
      next_tick = now + kLwipTickMs;
    }
    if (e->ppp_state == kPppEstablished && now >= e->next_echo_ms) {
      sstp_state_keepalive_tick(e->state);
      e->next_echo_ms = now + kEchoIntervalMs;
    }
  }
  // A clean end tells the server; the socket closes either way
  if (e->sstp_started && e->state != NULL && e->connection_error[0] == '\0' && e->ppp_state != kPppClose) {
    sstp_state_disconnect(e->state);
  }
  drain_wbio(e);
  if (e->out_len > 0) {
    int flags = fcntl(e->sock, F_GETFL);
    fcntl(e->sock, F_SETFL, flags & ~O_NONBLOCK);
    struct timeval limit = {.tv_sec = 1};
    setsockopt(e->sock, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit));
    (void)send(e->sock, e->out, e->out_len, MSG_NOSIGNAL);
  }
  report_end(e);
  ppp_end(e);
  pthread_mutex_lock(&e->tun_lock);
  e->tun = -1;
  pthread_cond_broadcast(&e->tun_swapped);
  pthread_mutex_unlock(&e->tun_lock);
  if (jvm != NULL && env != NULL) {
    (*jvm)->DetachCurrentThread(jvm);
  }
  return NULL;
}

#pragma mark - client certificate (SSProtocol.m)

// The leaf certificate and key of a PKCS#12 as PEM, with its CA certificates after the leaf
static bool p12_to_pem(const uint8_t *p12, size_t length, const char *passphrase, char **cert_pem, int *cert_len,
                       char **key_pem, int *key_len, X509 **leaf_out) {
  const uint8_t *bytes = p12;
  PKCS12 *pkcs12 = d2i_PKCS12(NULL, &bytes, (long)length);
  if (pkcs12 == NULL) {
    return false;
  }
  EVP_PKEY *key = NULL;
  X509 *cert = NULL;
  STACK_OF(X509) *ca = NULL;
  int ok = PKCS12_parse(pkcs12, passphrase, &key, &cert, &ca);
  PKCS12_free(pkcs12);
  bool done = false;
  if (ok == 1 && key != NULL && cert != NULL) {
    if (cert_pem != NULL) {
      BIO *out = BIO_new(BIO_s_mem());
      PEM_write_bio_X509(out, cert);
      for (int i = 0; ca != NULL && i < sk_X509_num(ca); i++) {
        PEM_write_bio_X509(out, sk_X509_value(ca, i));
      }
      char *data = NULL;
      long size = BIO_get_mem_data(out, &data);
      *cert_pem = malloc((size_t)size + 1);
      memcpy(*cert_pem, data, (size_t)size);
      (*cert_pem)[size] = '\0';
      *cert_len = (int)size;
      BIO_free(out);
      out = BIO_new(BIO_s_mem());
      PEM_write_bio_PrivateKey(out, key, NULL, NULL, 0, NULL, NULL);
      size = BIO_get_mem_data(out, &data);
      *key_pem = malloc((size_t)size + 1);
      memcpy(*key_pem, data, (size_t)size);
      (*key_pem)[size] = '\0';
      *key_len = (int)size;
      BIO_free(out);
    }
    done = true;
  }
  if (leaf_out != NULL && done) {
    *leaf_out = cert;
    cert = NULL;
  }
  EVP_PKEY_free(key);
  X509_free(cert);
  if (ca != NULL) sk_X509_pop_free(ca, X509_free);
  return done;
}

#pragma mark - JNI

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
  (void)reserved;
  jvm = vm;
  JNIEnv *env = NULL;
  if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
    return JNI_ERR;
  }
  jclass local = (*env)->FindClass(env, "tr/com/srp/vpn/Sstp");
  if (local == NULL) {
    return JNI_ERR;
  }
  sstp_class = (*env)->NewGlobalRef(env, local);
  trust_method = (*env)->GetStaticMethodID(env, sstp_class, "trustChain", "([[B)Ljava/lang/String;");
  return trust_method != NULL ? JNI_VERSION_1_6 : JNI_ERR;
}

static void copy_setting(JNIEnv *env, jobjectArray settings, int index, char *target, size_t size) {
  jstring value = (jstring)(*env)->GetObjectArrayElement(env, settings, index);
  target[0] = '\0';
  if (value == NULL) {
    return;
  }
  const char *text = (*env)->GetStringUTFChars(env, value, NULL);
  if (text != NULL) {
    snprintf(target, size, "%s", text);
    (*env)->ReleaseStringUTFChars(env, value, text);
  }
  (*env)->DeleteLocalRef(env, value);
}

static void stop_current(void) {
  pthread_mutex_lock(&engine_lock);
  engine_t *e = current;
  bool joinable = thread_running;
  pthread_mutex_unlock(&engine_lock);
  if (e != NULL) {
    atomic_store(&e->stop, true);
    wake(e);
  }
  if (joinable) {
    pthread_join(engine_thread, NULL);
  }
  pthread_mutex_lock(&engine_lock);
  if (current != NULL) {
    engine_free(current);
    current = NULL;
  }
  thread_running = false;
  pthread_mutex_unlock(&engine_lock);
}

// Keys of SstpClient.kt's settings array, in order
enum {
  kHost, kSni, kUser, kPassword, kPap, kChap, kMschap2, kEapMschapv2, kPeap, kPeapCb, kTtls, kTtlsInner, kTeap,
  kPrivacy, kAnonymous, kEapTls13, kEapLegacy, kInsecure, kLegacyOuter, kFragMode, kFragFirst, kFragFollowing,
  kCellular, kMschapBytewise, kMschapRetry, kSettingCount
};

JNIEXPORT jint JNICALL Java_tr_com_srp_vpn_Sstp_start(JNIEnv *env, jclass type, jint fd, jobjectArray settings,
                                                      jbyteArray p12, jstring passphrase) {
  (void)type;
  stop_current();
  if ((*env)->GetArrayLength(env, settings) != kSettingCount) {
    close(fd);
    return 0;
  }
  engine_t *e = calloc(1, sizeof(*e));
  if (e == NULL) {
    close(fd);
    return 0;
  }
  e->sock = fd;
  e->tun = -1;
  e->wake[0] = e->wake[1] = -1;
  pthread_mutex_init(&e->tun_lock, NULL);
  pthread_cond_init(&e->tun_swapped, NULL);
  char flag[16];
#define FLAG(index) (copy_setting(env, settings, index, flag, sizeof(flag)), strcmp(flag, "1") == 0)
  copy_setting(env, settings, kHost, e->host, sizeof(e->host));
  copy_setting(env, settings, kSni, e->sni, sizeof(e->sni));
  copy_setting(env, settings, kUser, e->username, sizeof(e->username));
  copy_setting(env, settings, kPassword, e->password, sizeof(e->password));
  e->pap = FLAG(kPap);
  e->chap = FLAG(kChap);
  e->mschap2 = FLAG(kMschap2);
  e->eap_mschapv2 = FLAG(kEapMschapv2);
  e->peap = FLAG(kPeap);
  e->peap_cb = FLAG(kPeapCb);
  e->ttls = FLAG(kTtls);
  copy_setting(env, settings, kTtlsInner, e->ttls_inner, sizeof(e->ttls_inner));
  e->teap = FLAG(kTeap);
  e->identity_privacy = FLAG(kPrivacy);
  copy_setting(env, settings, kAnonymous, e->anonymous, sizeof(e->anonymous));
  e->eap_tls13 = FLAG(kEapTls13);
  e->eap_disable_legacy = FLAG(kEapLegacy);
  e->allow_insecure = FLAG(kInsecure);
  e->disable_legacy_outer = FLAG(kLegacyOuter);
  copy_setting(env, settings, kFragMode, flag, sizeof(flag));
  e->frag_mode = atoi(flag);
  copy_setting(env, settings, kFragFirst, flag, sizeof(flag));
  e->frag_first = atoi(flag);
  copy_setting(env, settings, kFragFollowing, flag, sizeof(flag));
  e->frag_following = atoi(flag);
  e->cellular = FLAG(kCellular);
  e->mschap_bytewise = FLAG(kMschapBytewise);
  e->mschap_retry = FLAG(kMschapRetry);
#undef FLAG
  if (e->sni[0] == '\0') {
    snprintf(e->sni, sizeof(e->sni), "%s", e->host);
  }
  // TLS Fragmentation (SSFragTLSConfig): Auto from the ClientHello structure and the access network, Manual as typed
  if (e->frag_mode == 1) {
    e->split = true;
    e->first_chunk = 43;   // record header + handshake header + version + random: the SNI lands in a later write
    e->following_chunk = e->cellular ? 128 : 256;
    e->gap_ms = e->cellular ? 10 : 3;
  } else if (e->frag_mode == 2) {
    e->split = true;
    e->first_chunk = e->frag_first > 0 ? e->frag_first : 32;
    e->following_chunk = e->frag_following > 0 ? e->frag_following : 256;
    if (e->first_chunk > 4096 || e->following_chunk > 16384) {
      // Fail closed: this socket is plain TCP, continuing would send the SSTP handshake without the asked-for split
      snprintf(e->connection_error, sizeof(e->connection_error),
               "Invalid TLS fragmentation settings: chunk sizes out of bounds");
    }
  }
  e->burst_start = true;
  if (p12 != NULL) {
    jsize length = (*env)->GetArrayLength(env, p12);
    jbyte *bytes = (*env)->GetByteArrayElements(env, p12, NULL);
    const char *pass = passphrase != NULL ? (*env)->GetStringUTFChars(env, passphrase, NULL) : NULL;
    bool ok = bytes != NULL && p12_to_pem((const uint8_t *)bytes, (size_t)length, pass != NULL ? pass : "", &e->cert_pem,
                                          &e->cert_pem_len, &e->key_pem, &e->key_pem_len, NULL);
    if (pass != NULL) (*env)->ReleaseStringUTFChars(env, passphrase, pass);
    if (bytes != NULL) (*env)->ReleaseByteArrayElements(env, p12, bytes, JNI_ABORT);
    if (!ok) {
      snprintf(e->connection_error, sizeof(e->connection_error),
               "The client certificate could not be read. Re-import it in the profile.");
    }
  }
  int nodelay = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
  if (pipe(e->wake) != 0) {
    engine_free(e);
    return 0;
  }
  fcntl(e->wake[0], F_SETFL, O_NONBLOCK);
  fcntl(e->wake[1], F_SETFL, O_NONBLOCK);
  e->rx = malloc(kRecvBufferBytes);
  if (e->rx == NULL || sstp_stream_create(&e->stream, sstp_send, sstp_cert_hash, e) != SSTP_OKAY ||
      sstp_state_create(&e->state, e->stream, sstp_state_changed, e, SSTP_MODE_CLIENT) != SSTP_OKAY ||
      sstp_pppd_create(&e->pppd, e->stream, sstp_pppd_event, e) != SSTP_OKAY) {
    engine_free(e);
    return 0;
  }
  if (e->connection_error[0] != '\0') {
    atomic_store(&e->stop, true);
  }
  atomic_store(&log_bytes, 0);
  pthread_mutex_lock(&probe_lock);
  while (probe_head != NULL) {
    probe_packet_t *next = probe_head->next;
    free(probe_head);
    probe_head = next;
  }
  probe_tail = NULL;
  probe_queued = 0;
  probe_flow_count = 0;
  pthread_mutex_unlock(&probe_lock);
  pthread_mutex_lock(&engine_lock);
  generation++;
  current = e;
  thread_running = pthread_create(&engine_thread, NULL, engine_main, e) == 0;
  uint32_t started = thread_running ? generation : 0;
  pthread_mutex_unlock(&engine_lock);
  if (!thread_running) {
    stop_current();
  }
  return (jint)started;
}

JNIEXPORT void JNICALL Java_tr_com_srp_vpn_Sstp_stop(JNIEnv *env, jclass type) {
  (void)env;
  (void)type;
  stop_current();
}

// The tunnel's fd for this session's packets; returns once the engine took it, so the previous one can close
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_Sstp_attachTun(JNIEnv *env, jclass type, jint fd) {
  (void)env;
  (void)type;
  pthread_mutex_lock(&engine_lock);
  engine_t *e = thread_running ? current : NULL;
  if (e == NULL) {
    pthread_mutex_unlock(&engine_lock);
    return;
  }
  if (fd >= 0) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
  }
  pthread_mutex_lock(&e->tun_lock);
  e->pending_tun = fd;
  e->tun_pending = true;
  wake(e);
  struct timespec limit;
  clock_gettime(CLOCK_REALTIME, &limit);
  limit.tv_sec += 2;
  while (e->tun_pending && !atomic_load(&e->stop)) {
    if (pthread_cond_timedwait(&e->tun_swapped, &e->tun_lock, &limit) != 0) {
      break;
    }
  }
  pthread_mutex_unlock(&e->tun_lock);
  pthread_mutex_unlock(&engine_lock);
}

// Blocks up to timeoutMs for the next event: type, generation (4 bytes), payload; null when none came
JNIEXPORT jbyteArray JNICALL Java_tr_com_srp_vpn_Sstp_nextEvent(JNIEnv *env, jclass type, jint timeout_ms) {
  (void)type;
  pthread_mutex_lock(&event_lock);
  if (event_head == NULL && timeout_ms > 0) {
    struct timespec limit;
    clock_gettime(CLOCK_REALTIME, &limit);
    limit.tv_sec += timeout_ms / 1000;
    limit.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (limit.tv_nsec >= 1000000000L) {
      limit.tv_sec++;
      limit.tv_nsec -= 1000000000L;
    }
    while (event_head == NULL) {
      if (pthread_cond_timedwait(&event_ready, &event_lock, &limit) != 0) {
        break;
      }
    }
  }
  event_t *event = event_head;
  if (event != NULL) {
    event_head = event->next;
    if (event_head == NULL) {
      event_tail = NULL;
    }
  }
  pthread_mutex_unlock(&event_lock);
  if (event == NULL) {
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)(5 + event->length));
  uint8_t header[5] = {event->type, (uint8_t)event->generation, (uint8_t)(event->generation >> 8),
                       (uint8_t)(event->generation >> 16), (uint8_t)(event->generation >> 24)};
  (*env)->SetByteArrayRegion(env, result, 0, 5, (const jbyte *)header);
  if (event->length > 0) {
    (*env)->SetByteArrayRegion(env, result, 5, (jsize)event->length, (const jbyte *)event->bytes);
  }
  free(event);
  return result;
}

// A probe packet for PPP: 0 when queued, -EAGAIN for a full queue, -ENOTCONN while no session runs
JNIEXPORT jint JNICALL Java_tr_com_srp_vpn_Sstp_submit(JNIEnv *env, jclass type, jbyteArray packet) {
  (void)type;
  jsize length = (*env)->GetArrayLength(env, packet);
  if (length < 20 || length > 1500) {
    return -EINVAL;
  }
  pthread_mutex_lock(&engine_lock);
  engine_t *e = thread_running ? current : NULL;
  if (e == NULL) {
    pthread_mutex_unlock(&engine_lock);
    return -ENOTCONN;
  }
  probe_packet_t *item = malloc(sizeof(*item) + (size_t)length);
  if (item == NULL) {
    pthread_mutex_unlock(&engine_lock);
    return -ENOMEM;
  }
  item->next = NULL;
  item->length = (size_t)length;
  (*env)->GetByteArrayRegion(env, packet, 0, length, (jbyte *)item->bytes);
  pthread_mutex_lock(&probe_lock);
  int result = 0;
  if (probe_queued >= kMaxProbePackets) {
    free(item);
    result = -EAGAIN;
  } else {
    if (probe_tail != NULL) {
      probe_tail->next = item;
    } else {
      probe_head = item;
    }
    probe_tail = item;
    probe_queued++;
  }
  pthread_mutex_unlock(&probe_lock);
  if (result == 0) {
    wake(e);
  }
  pthread_mutex_unlock(&engine_lock);
  return result;
}

// Answers of these flows come back as events: triples of protocol, source IPv4 (as an int), destination port
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_Sstp_setProbeFlows(JNIEnv *env, jclass type, jintArray flows) {
  (void)type;
  jsize length = (*env)->GetArrayLength(env, flows);
  jint values[kMaxProbeFlows * 3];
  int count = length / 3 > kMaxProbeFlows ? kMaxProbeFlows : length / 3;
  (*env)->GetIntArrayRegion(env, flows, 0, count * 3, values);
  pthread_mutex_lock(&probe_lock);
  for (int i = 0; i < count; i++) {
    uint32_t source = (uint32_t)values[i * 3 + 1];
    probe_flows[i].protocol = values[i * 3];
    probe_flows[i].source[0] = (uint8_t)(source >> 24);
    probe_flows[i].source[1] = (uint8_t)(source >> 16);
    probe_flows[i].source[2] = (uint8_t)(source >> 8);
    probe_flows[i].source[3] = (uint8_t)source;
    probe_flows[i].destination_port = (uint16_t)values[i * 3 + 2];
  }
  probe_flow_count = count;
  pthread_mutex_unlock(&probe_lock);
}

JNIEXPORT void JNICALL Java_tr_com_srp_vpn_Sstp_setLog(JNIEnv *env, jclass type, jstring path, jint level) {
  (void)type;
  const char *text = (*env)->GetStringUTFChars(env, path, NULL);
  int fd = text != NULL ? open(text, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600) : -1;
  if (text != NULL) {
    (*env)->ReleaseStringUTFChars(env, path, text);
  }
  int previous = atomic_exchange(&log_fd, fd);
  if (previous >= 0) {
    close(previous);
  }
  atomic_store(&log_level, level);
}

// The certificate's name and expiry (seconds since 1970) for the editor, or null when the file or passphrase is wrong
JNIEXPORT jobjectArray JNICALL Java_tr_com_srp_vpn_Sstp_p12Info(JNIEnv *env, jclass type, jbyteArray p12,
                                                                 jstring passphrase) {
  (void)type;
  jsize length = (*env)->GetArrayLength(env, p12);
  jbyte *bytes = (*env)->GetByteArrayElements(env, p12, NULL);
  const char *pass = (*env)->GetStringUTFChars(env, passphrase, NULL);
  X509 *leaf = NULL;
  bool ok = bytes != NULL && pass != NULL &&
            p12_to_pem((const uint8_t *)bytes, (size_t)length, pass, NULL, NULL, NULL, NULL, &leaf);
  if (pass != NULL) (*env)->ReleaseStringUTFChars(env, passphrase, pass);
  if (bytes != NULL) (*env)->ReleaseByteArrayElements(env, p12, bytes, JNI_ABORT);
  if (!ok || leaf == NULL) {
    return NULL;
  }
  char name[256] = "";
  X509_NAME *subject = X509_get_subject_name(leaf);
  if (subject == NULL || X509_NAME_get_text_by_NID(subject, NID_commonName, name, sizeof(name)) <= 0) {
    snprintf(name, sizeof(name), "Client Certificate");
  }
  long long expiry = 0;
  int days = 0, seconds = 0;
  const ASN1_TIME *not_after = X509_get0_notAfter(leaf);
  if (not_after != NULL && ASN1_TIME_diff(&days, &seconds, NULL, not_after) == 1) {
    expiry = (long long)time(NULL) + (long long)days * 86400 + seconds;
  }
  X509_free(leaf);
  char expiry_text[32];
  snprintf(expiry_text, sizeof(expiry_text), "%lld", expiry);
  jobjectArray result = (*env)->NewObjectArray(env, 2, (*env)->FindClass(env, "java/lang/String"), NULL);
  (*env)->SetObjectArrayElement(env, result, 0, (*env)->NewStringUTF(env, name));
  (*env)->SetObjectArrayElement(env, result, 1, (*env)->NewStringUTF(env, expiry_text));
  return result;
}
