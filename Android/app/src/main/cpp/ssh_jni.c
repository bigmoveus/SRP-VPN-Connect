// The SSH VPN of the Android app: the iOS app's SSH bridge (iOS/Core/SRPCore/SRPSSHBridge.c: libssh2 and the
// hev-socks5-tunnel packet engine), started and stopped by SshClient.kt, which decides on reconnects as SRPSSHClient.m
// does. The engine reads and writes its "tun" through one end of a socket pair, as on iOS; this file moves the packets
// between the other end and the tunnel's fd, sends answers of the home screen's ping flows (probe flows, as in
// openconnect_tun_jni.c) to SshClient.kt instead of the tunnel, and queues the bridge's events for SshClient.kt. The app
// stays outside its own tunnel, so the SSH socket needs no protect().

#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "SRPSSHBridge.h"

enum { kMaxProbeFlows = 4, kMaxPacket = 65535, kSocketBuffer = 2 * 1024 * 1024, kMaxProbeQueue = 64, kBatch = 64,
       kMaxEvents = 512 };

typedef struct probe {
  struct probe *next;
  size_t length;
  uint8_t bytes[];
} probe_t;

typedef struct {
  int protocol;
  uint8_t source[4];
  uint16_t destination_port;
} probe_flow_t;

typedef struct event {
  struct event *next;
  char text[];   // "generation|type|code|text": type L (log, code = level), R (ready), F (failure, code = SRPSSHError), G (gone)
} event_t;

static pthread_mutex_t session_lock = PTHREAD_MUTEX_INITIALIZER;
static int pair_fds[2] = {-1, -1};   // [0] the engine's tun, [1] the pump's end
static atomic_int tun_fd = -1;
static int wake[2] = {-1, -1};
static pthread_t pump_thread;
static bool pump_running;
static bool bridge_running;
static atomic_int generation;

static pthread_mutex_t probe_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t probe_ready = PTHREAD_COND_INITIALIZER;
static int probe_flow_count;
static probe_flow_t probe_flows[kMaxProbeFlows];
static probe_t *probe_head, *probe_tail;
static int probe_queued;

static pthread_mutex_t event_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t event_ready = PTHREAD_COND_INITIALIZER;
static event_t *event_head, *event_tail;
static int events_queued;

#pragma mark - events

static void push_event(char type, int code, const char *text) {
  size_t length = strlen(text ? text : "") + 32;
  event_t *event = malloc(sizeof(*event) + length);
  if (event == NULL) {
    return;
  }
  event->next = NULL;
  snprintf(event->text, length, "%d|%c|%d|%s", atomic_load(&generation), type, code, text ? text : "");
  // NewStringUTF takes modified UTF-8 only: a byte outside ASCII (a name typed in another script) shows as "?"
  for (char *c = event->text; *c; c++) {
    if ((unsigned char)*c >= 0x80) {
      *c = '?';
    }
  }
  pthread_mutex_lock(&event_lock);
  if (events_queued >= kMaxEvents) {   // nobody reads them: keep the newest
    event_t *oldest = event_head;
    event_head = oldest->next;
    if (event_head == NULL) {
      event_tail = NULL;
    }
    free(oldest);
    events_queued--;
  }
  if (event_tail != NULL) {
    event_tail->next = event;
  } else {
    event_head = event;
  }
  event_tail = event;
  events_queued++;
  pthread_cond_signal(&event_ready);
  pthread_mutex_unlock(&event_lock);
}

static void on_log(void *ctx, int level, const char *line) {
  (void)ctx;
  push_event('L', level, line);
}

static void on_ready(void *ctx) {
  (void)ctx;
  push_event('R', 0, "");
}

static void on_fail(void *ctx, SRPSSHError error, const char *detail) {
  (void)ctx;
  push_event('F', (int)error, detail);
}

static void on_gone(void *ctx, const char *reason) {
  (void)ctx;
  push_event('G', 0, reason);
}

#pragma mark - probes

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

static void queue_probe(const uint8_t *packet, size_t length) {
  probe_t *probe = malloc(sizeof(*probe) + length);
  if (probe == NULL) {
    return;
  }
  probe->next = NULL;
  probe->length = length;
  memcpy(probe->bytes, packet, length);
  pthread_mutex_lock(&probe_lock);
  if (probe_queued >= kMaxProbeQueue) {   // nobody reads them: keep the newest
    probe_t *oldest = probe_head;
    probe_head = oldest->next;
    if (probe_head == NULL) {
      probe_tail = NULL;
    }
    free(oldest);
    probe_queued--;
  }
  if (probe_tail != NULL) {
    probe_tail->next = probe;
  } else {
    probe_head = probe;
  }
  probe_tail = probe;
  probe_queued++;
  pthread_cond_signal(&probe_ready);
  pthread_mutex_unlock(&probe_lock);
}

static void clear_probes(void) {
  pthread_mutex_lock(&probe_lock);
  while (probe_head != NULL) {
    probe_t *next = probe_head->next;
    free(probe_head);
    probe_head = next;
  }
  probe_tail = NULL;
  probe_queued = 0;
  probe_flow_count = 0;
  pthread_mutex_unlock(&probe_lock);
}

#pragma mark - packet pump

// One thread, both directions, non-blocking. A packet from the tunnel that the engine cannot take yet (its queue is
// full) waits as `pending`, and the tunnel is not read until it went: backpressure instead of loss.
static void *pump(void *argument) {
  int own = (int)(intptr_t)argument;
  uint8_t *packet = malloc(kMaxPacket);
  uint8_t *pending = malloc(kMaxPacket);
  ssize_t pending_length = 0;
  while (packet != NULL && pending != NULL) {
    int fd = atomic_load(&tun_fd);
    struct pollfd fds[3] = {{wake[0], POLLIN, 0}, {own, (short)(POLLIN | (pending_length > 0 ? POLLOUT : 0)), 0},
                            {fd, POLLIN, 0}};
    int ready = poll(fds, (fd >= 0 && pending_length == 0) ? 3 : 2, -1);
    if (ready < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    if (fds[0].revents & POLLIN) {
      char drain[16];
      ssize_t got = read(wake[0], drain, sizeof(drain));
      if (got > 0 && memchr(drain, 'q', (size_t)got) != NULL) {
        break;
      }
      continue;   // the tunnel's fd changed
    }
    if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
      break;
    }
    // the engine -> the tunnel (or a probe answer)
    if (fds[1].revents & POLLIN) {
      for (int i = 0; i < kBatch; i++) {
        ssize_t length = recv(own, packet, kMaxPacket, MSG_DONTWAIT);
        if (length <= 0) {
          break;
        }
        if (matches_probe_flow(packet, (size_t)length)) {
          queue_probe(packet, (size_t)length);
        } else if (fd >= 0) {
          (void)write(fd, packet, (size_t)length);   // a full tunnel queue drops it, as a network would
        }
      }
    }
    // A packet that waited for room
    if (pending_length > 0 && (fds[1].revents & POLLOUT)) {
      if (send(own, pending, (size_t)pending_length, MSG_DONTWAIT) >= 0 || (errno != EAGAIN && errno != ENOBUFS)) {
        pending_length = 0;
      }
    }
    // the tunnel -> the engine
    if (fd >= 0 && pending_length == 0 && (fds[2].revents & POLLIN)) {
      for (int i = 0; i < kBatch; i++) {
        ssize_t length = read(fd, packet, kMaxPacket);
        if (length <= 0) {
          break;
        }
        int version = packet[0] >> 4;
        if (version != 4 && version != 6) {
          continue;
        }
        if (send(own, packet, (size_t)length, MSG_DONTWAIT) < 0) {
          if (errno == EAGAIN || errno == ENOBUFS) {
            memcpy(pending, packet, (size_t)length);
            pending_length = length;
          }
          break;
        }
      }
    }
  }
  free(packet);
  free(pending);
  return NULL;
}

static void wake_pump(char byte) {
  if (wake[1] >= 0) {
    (void)write(wake[1], &byte, 1);
  }
}

// The bridge first (it joins its session thread and the engine), then the pump and the channel
static void stop_locked(void) {
  if (bridge_running) {
    srpssh_stop();
    bridge_running = false;
  }
  if (pump_running) {
    wake_pump('q');
    pthread_join(pump_thread, NULL);
    pump_running = false;
  }
  for (int i = 0; i < 2; i++) {
    if (pair_fds[i] >= 0) {
      close(pair_fds[i]);
      pair_fds[i] = -1;
    }
    if (wake[i] >= 0) {
      close(wake[i]);
      wake[i] = -1;
    }
  }
  clear_probes();
}

static const char *utf(JNIEnv *env, jstring text, const char **held) {
  *held = text != NULL ? (*env)->GetStringUTFChars(env, text, NULL) : NULL;
  return *held;
}

#pragma mark - JNI

// A new session: a new packet channel and the bridge on it, after the previous session stopped. Its events carry
// `session`. 0 when started, -1 otherwise.
JNIEXPORT jint JNICALL Java_tr_com_srp_vpn_SshNative_start(JNIEnv *env, jclass type, jint session, jstring host, jint port,
                                                           jstring username, jstring password, jstring host_key,
                                                           jboolean udp, jint log_level) {
  (void)type;
  pthread_mutex_lock(&session_lock);
  stop_locked();
  atomic_store(&generation, session);
  int result = -1;
  if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, pair_fds) == 0 && pipe(wake) == 0) {
    for (int i = 0; i < 2; i++) {
      int size = kSocketBuffer;
      setsockopt(pair_fds[i], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
      setsockopt(pair_fds[i], SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    }
    fcntl(wake[0], F_SETFL, fcntl(wake[0], F_GETFL) | O_NONBLOCK);
    fcntl(pair_fds[1], F_SETFL, fcntl(pair_fds[1], F_GETFL) | O_NONBLOCK);
    pump_running = pthread_create(&pump_thread, NULL, pump, (void *)(intptr_t)pair_fds[1]) == 0;
    if (pump_running) {
      const char *held[4];
      SRPSSHBridgeConfig config;
      memset(&config, 0, sizeof(config));
      config.host = utf(env, host, &held[0]);
      config.port = port;
      config.username = utf(env, username, &held[1]);
      config.password = utf(env, password, &held[2]);
      config.hostkey_sha256 = utf(env, host_key, &held[3]);
      if (config.hostkey_sha256 != NULL && config.hostkey_sha256[0] == 0) {
        config.hostkey_sha256 = NULL;
      }
      config.udp_enabled = udp ? 1 : 0;
      config.relay_host = "127.0.0.1";
      config.relay_port = 1080;
      config.mtu = 1400;
      config.tun_ipv4 = "198.18.0.1";
      config.log_level = log_level;
      config.keepalive_seconds = 15;
      // the bridge keeps its own copies of the strings
      bridge_running = srpssh_start(&config, pair_fds[0], on_log, NULL, on_ready, on_fail, on_gone, NULL) == 0;
      jstring strings[4] = {host, username, password, host_key};
      for (int i = 0; i < 4; i++) {
        if (held[i] != NULL) {
          (*env)->ReleaseStringUTFChars(env, strings[i], held[i]);
        }
      }
      result = bridge_running ? 0 : -1;
    }
  }
  if (result < 0) {
    stop_locked();
  }
  pthread_mutex_unlock(&session_lock);
  return result;
}

// Ends the session: no event of it comes after this returns
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_SshNative_stop(JNIEnv *env, jclass type) {
  (void)env;
  (void)type;
  pthread_mutex_lock(&session_lock);
  stop_locked();
  pthread_mutex_unlock(&session_lock);
}

// The tunnel's fd (-1: none); the previous one can close once this returns
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_SshNative_attachTun(JNIEnv *env, jclass type, jint fd) {
  (void)env;
  (void)type;
  if (fd >= 0) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
  }
  atomic_store(&tun_fd, fd);
  wake_pump('w');
}

// A probe packet into the engine, as if an app had sent it: 0 when sent, a negative errno otherwise
JNIEXPORT jint JNICALL Java_tr_com_srp_vpn_SshNative_submit(JNIEnv *env, jclass type, jbyteArray packet) {
  (void)type;
  jsize length = (*env)->GetArrayLength(env, packet);
  jbyte *bytes = (*env)->GetByteArrayElements(env, packet, NULL);
  if (bytes == NULL) {
    return -ENOMEM;
  }
  pthread_mutex_lock(&session_lock);
  int result = pair_fds[1] >= 0 ? (send(pair_fds[1], bytes, (size_t)length, MSG_DONTWAIT) >= 0 ? 0 : -errno) : -ENOTCONN;
  pthread_mutex_unlock(&session_lock);
  (*env)->ReleaseByteArrayElements(env, packet, bytes, JNI_ABORT);
  return result;
}

// Answers of these flows come back through nextProbe: triples of protocol, source IPv4, destination port
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_SshNative_setProbeFlows(JNIEnv *env, jclass type, jintArray flows) {
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

static void deadline_after(struct timespec *limit, int timeout_ms) {
  clock_gettime(CLOCK_REALTIME, limit);
  limit->tv_sec += timeout_ms / 1000;
  limit->tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
  if (limit->tv_nsec >= 1000000000L) {
    limit->tv_sec++;
    limit->tv_nsec -= 1000000000L;
  }
}

// Blocks up to timeoutMs for the next probe answer; null when none came
JNIEXPORT jbyteArray JNICALL Java_tr_com_srp_vpn_SshNative_nextProbe(JNIEnv *env, jclass type, jint timeout_ms) {
  (void)type;
  pthread_mutex_lock(&probe_lock);
  if (probe_head == NULL && timeout_ms > 0) {
    struct timespec limit;
    deadline_after(&limit, timeout_ms);
    while (probe_head == NULL) {
      if (pthread_cond_timedwait(&probe_ready, &probe_lock, &limit) != 0) {
        break;
      }
    }
  }
  probe_t *probe = probe_head;
  if (probe != NULL) {
    probe_head = probe->next;
    if (probe_head == NULL) {
      probe_tail = NULL;
    }
    probe_queued--;
  }
  pthread_mutex_unlock(&probe_lock);
  if (probe == NULL) {
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)probe->length);
  if (result != NULL) {
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)probe->length, (const jbyte *)probe->bytes);
  }
  free(probe);
  return result;
}

// Blocks up to timeoutMs for the bridge's next event ("generation|type|code|text"); null when none came
JNIEXPORT jstring JNICALL Java_tr_com_srp_vpn_SshNative_nextEvent(JNIEnv *env, jclass type, jint timeout_ms) {
  (void)type;
  pthread_mutex_lock(&event_lock);
  if (event_head == NULL && timeout_ms > 0) {
    struct timespec limit;
    deadline_after(&limit, timeout_ms);
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
    events_queued--;
  }
  pthread_mutex_unlock(&event_lock);
  if (event == NULL) {
    return NULL;
  }
  jstring result = (*env)->NewStringUTF(env, event->text);
  free(event);
  return result;
}
