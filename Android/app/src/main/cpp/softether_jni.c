// The SoftEther client of the iOS app on Android: the same client core (iOS/SoftEther: Mayaqua, Cedar and the SRPSE
// bridge) behind the API that SRPSoftEtherClient.m uses on iOS. The core runs its own threads and sockets (the app stays
// outside its own tunnel, so they need no protect()); this file moves its packets to and from the tunnel's fd, queues its
// events for SoftEtherClient.kt, which decides on reconnects as SRPSoftEtherClient.m does, and checks the server's
// certificate with the platform's trust manager, as SecTrust does on iOS.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "SRPSEClient.h"

enum { kEventConfig = 1, kEventState = 2, kEventProbePacket = 3, kEventConfig6 = 4 };
enum { kMaxProbeFlows = 4, kLogCapBytes = 2 * 1024 * 1024, kMaxPacket = 65535 };

typedef struct event {
  struct event *next;
  uint32_t generation;
  uint8_t type;
  size_t length;
  uint8_t bytes[];
} event_t;

static JavaVM *jvm;
static jclass se_class;
static jmethodID trust_method;

static pthread_mutex_t event_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t event_ready = PTHREAD_COND_INITIALIZER;
static event_t *event_head, *event_tail;

// start, stop and the session's client; injections hold the read lock so stop can free the client safely
static pthread_mutex_t session_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_rwlock_t client_lock = PTHREAD_RWLOCK_INITIALIZER;
static SRPSEClient *client;
static uint32_t generation;

static atomic_int tun_fd = -1;
static int tun_wake[2] = {-1, -1};
static pthread_t tun_thread;
static bool tun_thread_running;

typedef struct {
  int protocol;
  uint8_t source[4];
  uint16_t destination_port;
} probe_flow_t;

static pthread_mutex_t probe_lock = PTHREAD_MUTEX_INITIALIZER;
static int probe_flow_count;
static probe_flow_t probe_flows[kMaxProbeFlows];

static atomic_int log_fd = -1;
static atomic_int log_level;
static atomic_llong log_bytes;

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

static void post_event(uint32_t event_generation, uint8_t type, const void *bytes, size_t length) {
  event_t *event = malloc(sizeof(*event) + length);
  if (event == NULL) {
    return;
  }
  event->next = NULL;
  event->generation = event_generation;
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
static void post_strings(uint32_t event_generation, uint8_t type, const char *const *texts, int count) {
  size_t length = 0;
  for (int i = 0; i < count; i++) {
    length += strlen(texts[i] != NULL ? texts[i] : "") + 1;
  }
  char *payload = malloc(length > 0 ? length : 1);
  if (payload == NULL) {
    return;
  }
  size_t offset = 0;
  for (int i = 0; i < count; i++) {
    const char *text = texts[i] != NULL ? texts[i] : "";
    size_t size = strlen(text) + 1;
    memcpy(payload + offset, text, size);
    offset += size;
  }
  post_event(event_generation, type, payload, length);
  free(payload);
}

#pragma mark - callbacks of the core (its own threads)

static bool matches_probe_flow(const uint8_t *packet, size_t length) {
  if (length < 24 || (packet[0] >> 4) != 4) {
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

static void on_packet(void *ctx, const uint8_t *packet, uint32_t length, int family) {
  (void)family;
  if (matches_probe_flow(packet, length)) {
    post_event((uint32_t)(uintptr_t)ctx, kEventProbePacket, packet, length);
    return;
  }
  int fd = atomic_load(&tun_fd);
  if (fd >= 0) {
    // A full tunnel queue drops the packet, as a network would; TCP sends it again
    (void)write(fd, packet, length);
  }
}

static void on_config(void *ctx, const char *ip, const char *mask, const char *gateway, const char *dns, uint32_t lease) {
  (void)lease;
  const char *texts[] = {ip, mask, gateway, dns};
  post_strings((uint32_t)(uintptr_t)ctx, kEventConfig, texts, 4);
}

static void on_config6(void *ctx, const char *address, int prefix, const char *gateway, const char *dns, uint32_t lifetime) {
  (void)lifetime;
  char prefix_text[8];
  snprintf(prefix_text, sizeof(prefix_text), "%d", prefix);
  const char *texts[] = {address, prefix_text, gateway, dns};
  post_strings((uint32_t)(uintptr_t)ctx, kEventConfig6, texts, 4);
}

static void on_state(void *ctx, int status, uint32_t error) {
  char status_text[16], error_text[16];
  snprintf(status_text, sizeof(status_text), "%d", status);
  snprintf(error_text, sizeof(error_text), "%u", error);
  const char *texts[] = {status_text, error_text};
  post_strings((uint32_t)(uintptr_t)ctx, kEventState, texts, 2);
}

static void on_log(void *ctx, const char *line) {
  (void)ctx;
  slog(1, "[se] %s", line);
}

static bool is_ip_literal(const char *text) {
  struct in6_addr address;
  return inet_pton(AF_INET, text, &address) == 1 || inet_pton(AF_INET6, text, &address) == 1;
}

// The server's chain (leaf first) against the verification name, then the platform's trust manager through
// SoftEther.trustChain: 0 to go on, or the SoftEther error the core reports (85 not trusted, 149 name mismatch)
static uint32_t on_trust(void *ctx, const uint8_t *const *chain, const size_t *lengths, int count, const char *hostname) {
  (void)ctx;
  if (count <= 0) {
    return 85;
  }
  const unsigned char *bytes = chain[0];
  X509 *leaf = d2i_X509(NULL, &bytes, (long)lengths[0]);
  if (leaf == NULL) {
    return 85;
  }
  const char *name = hostname != NULL ? hostname : "";
  int matches = is_ip_literal(name) ? X509_check_ip_asc(leaf, name, 0) : X509_check_host(leaf, name, 0, 0, NULL);
  X509_free(leaf);
  if (matches != 1) {
    slog(0, "SoftEther TLS: the server certificate is not for %s", name);
    return 149;
  }
  JNIEnv *env = NULL;
  bool attached = false;
  if ((*jvm)->GetEnv(jvm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
    if ((*jvm)->AttachCurrentThread(jvm, &env, NULL) != JNI_OK) {
      return 85;
    }
    attached = true;
  }
  jclass byte_array = (*env)->FindClass(env, "[B");
  jobjectArray array = (*env)->NewObjectArray(env, count, byte_array, NULL);
  for (int i = 0; i < count; i++) {
    jbyteArray der = (*env)->NewByteArray(env, (jsize)lengths[i]);
    (*env)->SetByteArrayRegion(env, der, 0, (jsize)lengths[i], (const jbyte *)chain[i]);
    (*env)->SetObjectArrayElement(env, array, i, der);
    (*env)->DeleteLocalRef(env, der);
  }
  jstring answer = (jstring)(*env)->CallStaticObjectMethod(env, se_class, trust_method, array);
  uint32_t result = 0;
  if ((*env)->ExceptionCheck(env)) {
    (*env)->ExceptionClear(env);
    result = 85;
  } else if (answer != NULL) {
    const char *text = (*env)->GetStringUTFChars(env, answer, NULL);
    slog(0, "SoftEther TLS: certificate not trusted for %s: %s", name, text != NULL ? text : "not trusted");
    if (text != NULL) {
      (*env)->ReleaseStringUTFChars(env, answer, text);
    }
    (*env)->DeleteLocalRef(env, answer);
    result = 85;
  } else {
    slog(1, "SoftEther TLS: server certificate trusted for %s", name);
  }
  (*env)->DeleteLocalRef(env, array);
  (*env)->DeleteLocalRef(env, byte_array);
  if (attached) {
    (*jvm)->DetachCurrentThread(jvm);
  }
  return result;
}

#pragma mark - the tunnel's packets into the core

static void *tun_pump(void *argument) {
  (void)argument;
  uint8_t *packet = malloc(kMaxPacket);
  while (packet != NULL) {
    int fd = atomic_load(&tun_fd);
    struct pollfd fds[2] = {{tun_wake[0], POLLIN, 0}, {fd, POLLIN, 0}};
    int ready = poll(fds, fd >= 0 ? 2 : 1, -1);
    if (ready < 0 && errno != EINTR) {
      break;
    }
    if (fds[0].revents & POLLIN) {
      char drain[16];
      ssize_t got = read(tun_wake[0], drain, sizeof(drain));
      if (got > 0 && drain[got - 1] == 'q') {
        break;   // the library is going away
      }
      continue;   // the fd changed
    }
    if (fd < 0 || !(fds[1].revents & POLLIN)) {
      continue;
    }
    for (int i = 0; i < 64; i++) {
      ssize_t length = read(fd, packet, kMaxPacket);
      if (length <= 0) {
        break;
      }
      int version = packet[0] >> 4;
      if (version != 4 && version != 6) {
        continue;
      }
      pthread_rwlock_rdlock(&client_lock);
      if (client != NULL) {
        SRPSEClientInjectPacket(client, packet, (uint32_t)length, version);
      }
      pthread_rwlock_unlock(&client_lock);
    }
  }
  free(packet);
  return NULL;
}

static void wake_pump(char byte) {
  if (tun_wake[1] >= 0) {
    (void)write(tun_wake[1], &byte, 1);
  }
}

#pragma mark - JNI

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
  (void)reserved;
  jvm = vm;
  JNIEnv *env = NULL;
  if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
    return JNI_ERR;
  }
  jclass local = (*env)->FindClass(env, "tr/com/srp/vpn/SoftEther");
  if (local == NULL) {
    return JNI_ERR;
  }
  se_class = (*env)->NewGlobalRef(env, local);
  trust_method = (*env)->GetStaticMethodID(env, se_class, "trustChain", "([[B)Ljava/lang/String;");
  return trust_method != NULL ? JNI_VERSION_1_6 : JNI_ERR;
}

// Once per process: the core's writable directory (its log and marker files) and the tunnel pump
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_SoftEther_init(JNIEnv *env, jclass type, jstring directory, jboolean debug) {
  (void)type;
  static bool done = false;
  pthread_mutex_lock(&session_lock);
  if (!done) {
    const char *text = (*env)->GetStringUTFChars(env, directory, NULL);
    SRPSEGlobalInit(text != NULL ? text : ".", debug == JNI_TRUE);
    if (text != NULL) {
      (*env)->ReleaseStringUTFChars(env, directory, text);
    }
    if (pipe(tun_wake) == 0) {
      fcntl(tun_wake[0], F_SETFL, fcntl(tun_wake[0], F_GETFL) | O_NONBLOCK);
      tun_thread_running = pthread_create(&tun_thread, NULL, tun_pump, NULL) == 0;
    }
    done = true;
  }
  pthread_mutex_unlock(&session_lock);
}

static void copy_setting(JNIEnv *env, jobjectArray settings, int index, char *target, size_t size) {
  target[0] = '\0';
  if (index >= (*env)->GetArrayLength(env, settings)) {
    return;
  }
  jstring value = (jstring)(*env)->GetObjectArrayElement(env, settings, index);
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

static long number_setting(JNIEnv *env, jobjectArray settings, int index) {
  char text[32];
  copy_setting(env, settings, index, text, sizeof(text));
  return strtol(text, NULL, 10);
}

static void stop_locked(void) {
  pthread_rwlock_wrlock(&client_lock);
  SRPSEClient *old = client;
  client = NULL;
  pthread_rwlock_unlock(&client_lock);
  if (old != NULL) {
    SRPSEClientFree(old);   // blocks until the session's threads have ended
  }
}

/*
 * A new session with the settings in SoftEtherClient.kt's order: host, port, hub, hostname override, username, password,
 * auth type, verify, connections, UDP acceleration, NAT-T, NAT-T hint, proxy type, proxy host, proxy port, proxy username,
 * proxy password, first chunk, following chunks, chunk gap. Returns the generation that tags its events, 0 when it did
 * not start, -2 when the client certificate could not be read.
 */
JNIEXPORT jint JNICALL Java_tr_com_srp_vpn_SoftEther_start(JNIEnv *env, jclass type, jobjectArray settings, jbyteArray p12,
                                                          jstring passphrase) {
  (void)type;
  pthread_mutex_lock(&session_lock);
  stop_locked();
  SRPSEClientConfig config;
  memset(&config, 0, sizeof(config));
  char text[16];
  copy_setting(env, settings, 0, config.hostname, sizeof(config.hostname));
  config.port = (uint16_t)number_setting(env, settings, 1);
  copy_setting(env, settings, 2, config.hub, sizeof(config.hub));
  copy_setting(env, settings, 3, config.sniOverride, sizeof(config.sniOverride));
  copy_setting(env, settings, 4, config.username, sizeof(config.username));
  copy_setting(env, settings, 5, config.password, sizeof(config.password));
  config.authType = (SRPSEAuthType)number_setting(env, settings, 6);
  copy_setting(env, settings, 7, text, sizeof(text));
  config.tlsVerify = strcmp(text, "1") == 0;
  config.maxConnections = (uint32_t)number_setting(env, settings, 8);
  copy_setting(env, settings, 9, text, sizeof(text));
  config.udpAcceleration = strcmp(text, "1") == 0;
  copy_setting(env, settings, 10, text, sizeof(text));
  config.natTraversal = strcmp(text, "1") == 0;
  copy_setting(env, settings, 11, config.natTHint, sizeof(config.natTHint));
  config.proxyType = (SRPSEProxyType)number_setting(env, settings, 12);
  copy_setting(env, settings, 13, config.proxyHost, sizeof(config.proxyHost));
  config.proxyPort = (uint16_t)number_setting(env, settings, 14);
  copy_setting(env, settings, 15, config.proxyUsername, sizeof(config.proxyUsername));
  copy_setting(env, settings, 16, config.proxyPassword, sizeof(config.proxyPassword));
  config.tlsFragFirst = (uint32_t)number_setting(env, settings, 17);
  config.tlsFragFollowing = (uint32_t)number_setting(env, settings, 18);
  config.tlsFragGapMs = (uint32_t)number_setting(env, settings, 19);
  config.useCompress = true;
  config.retryIntervalSec = 5;
  jbyte *p12_bytes = NULL;
  if (p12 != NULL) {
    p12_bytes = (*env)->GetByteArrayElements(env, p12, NULL);
    config.p12 = (const uint8_t *)p12_bytes;
    config.p12Len = (size_t)(*env)->GetArrayLength(env, p12);
    if (passphrase != NULL) {
      const char *value = (*env)->GetStringUTFChars(env, passphrase, NULL);
      if (value != NULL) {
        snprintf(config.p12Passphrase, sizeof(config.p12Passphrase), "%s", value);
        (*env)->ReleaseStringUTFChars(env, passphrase, value);
      }
    }
  }
  SRPSESetTrustHook(NULL, config.tlsVerify ? on_trust : NULL);
  uint32_t next = generation + 1 == 0 ? 1 : generation + 1;
  SRPSEClient *created = SRPSEClientCreate(&config, (void *)(uintptr_t)next, on_packet, on_config, on_config6, on_state,
                                           on_log);
  jint result = 0;
  if (created != NULL) {
    int started = SRPSEClientStart(created);
    if (started == 0) {
      generation = next;
      pthread_rwlock_wrlock(&client_lock);
      client = created;
      pthread_rwlock_unlock(&client_lock);
      result = (jint)next;
    } else {
      SRPSEClientFree(created);
      result = started == -2 ? -2 : 0;
    }
  }
  if (p12_bytes != NULL) {
    (*env)->ReleaseByteArrayElements(env, p12, p12_bytes, JNI_ABORT);
  }
  memset(config.password, 0, sizeof(config.password));
  memset(config.proxyPassword, 0, sizeof(config.proxyPassword));
  memset(config.p12Passphrase, 0, sizeof(config.p12Passphrase));
  pthread_mutex_unlock(&session_lock);
  return result;
}

// Ends the session and blocks until its threads have ended
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_SoftEther_stop(JNIEnv *env, jclass type) {
  (void)env;
  (void)type;
  pthread_mutex_lock(&session_lock);
  stop_locked();
  pthread_mutex_unlock(&session_lock);
}

// The tunnel's fd for the packets (-1: none); the caller closes the previous one after this returns
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_SoftEther_attachTun(JNIEnv *env, jclass type, jint fd) {
  (void)env;
  (void)type;
  if (fd >= 0) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
  }
  atomic_store(&tun_fd, fd);
  wake_pump('w');
}

// Blocks up to timeoutMs for the next event: type, generation (4 bytes), payload; null when none came
JNIEXPORT jbyteArray JNICALL Java_tr_com_srp_vpn_SoftEther_nextEvent(JNIEnv *env, jclass type, jint timeout_ms) {
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

// A probe packet into the tunnel (the home screen's ping): 0 when sent, -ENOTCONN while no session runs
JNIEXPORT jint JNICALL Java_tr_com_srp_vpn_SoftEther_submit(JNIEnv *env, jclass type, jbyteArray packet) {
  (void)type;
  jsize length = (*env)->GetArrayLength(env, packet);
  if (length < 20 || length > 1500) {
    return -EINVAL;
  }
  uint8_t bytes[1500];
  (*env)->GetByteArrayRegion(env, packet, 0, length, (jbyte *)bytes);
  jint result = -ENOTCONN;
  pthread_rwlock_rdlock(&client_lock);
  if (client != NULL) {
    SRPSEClientInjectPacket(client, bytes, (uint32_t)length, bytes[0] >> 4);
    result = 0;
  }
  pthread_rwlock_unlock(&client_lock);
  return result;
}

// Answers of these flows come back as events: triples of protocol, source IPv4 (as an int), destination port
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_SoftEther_setProbeFlows(JNIEnv *env, jclass type, jintArray flows) {
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

JNIEXPORT void JNICALL Java_tr_com_srp_vpn_SoftEther_setLog(JNIEnv *env, jclass type, jstring path, jint level) {
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
  atomic_store(&log_bytes, 0);
  // The core prints its own progress to stdout (Debug() in Mayaqua); like the iOS extension, it goes to the tunnel log
  if (fd >= 0) {
    fflush(stdout);
    if (dup2(fd, STDOUT_FILENO) >= 0) {
      setvbuf(stdout, NULL, _IOLBF, 0);
    }
  }
}

JNIEXPORT jstring JNICALL Java_tr_com_srp_vpn_SoftEther_errorName(JNIEnv *env, jclass type, jint code) {
  (void)type;
  return (*env)->NewStringUTF(env, SRPSEErrorName((uint32_t)code));
}
