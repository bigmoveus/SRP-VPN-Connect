#include "SRPWaterWallBridge.h"

#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <maxminddb.h>
#include <poll.h>
#include <pthread.h>
#include <sodium.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

// One runtime per process, as the bridge allows. Everything here runs for WaterWallClient, which calls start, stop,
// submit and the settings from one worker thread; its event thread sits in nextEvent.

enum { kEventReady = 1, kEventFailure = 2, kEventProbePacket = 3, kEventChannelStopped = 4 };
enum { kMaxProbeFlows = 4 };
enum { kReadAheadBytes = 8 * 1024 * 1024 };
enum { kLogCapBytes = 2 * 1024 * 1024, kLogKeepBytes = 512 * 1024 };

typedef struct event {
  struct event *next;
  uint32_t generation;
  uint8_t type;
  int32_t code;
  size_t length;
  uint8_t bytes[];
} event_t;

typedef struct held_packet {
  struct held_packet *next;
  size_t length;
  uint8_t bytes[];
} held_packet_t;

typedef struct {
  int protocol;
  uint8_t source[4];
  uint16_t destination_port;
} probe_flow_t;

static pthread_mutex_t event_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t event_ready = PTHREAD_COND_INITIALIZER;
static event_t *event_head;
static event_t *event_tail;

static pthread_mutex_t bridge_lock = PTHREAD_MUTEX_INITIALIZER;
static SRPWaterWallBridge *bridge;
static uint32_t generation;

static atomic_int tun_fd = -1;
static pthread_t reader;
static bool reader_running;
static atomic_bool reader_stop;
static atomic_bool accepting;
static atomic_bool channel_stop_reported;

static atomic_llong last_payload_ms;

static pthread_mutex_t probe_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_int probe_flow_count;
static probe_flow_t probe_flows[kMaxProbeFlows];

static atomic_int log_fd = -1;
static atomic_int log_level;
static atomic_llong log_bytes;
static pthread_mutex_t log_cap_lock = PTHREAD_MUTEX_INITIALIZER;

// Only the reader thread touches these.
static held_packet_t *held_head;
static held_packet_t *held_tail;
static size_t held_bytes;

static long long uptimeMs(void) {
  struct timespec now;
  clock_gettime(CLOCK_BOOTTIME, &now);
  return (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void postEvent(uint32_t event_generation, uint8_t type, int32_t code, const void *bytes, size_t length) {
  event_t *event = malloc(sizeof(*event) + length);
  if (event == NULL) {
    return;
  }
  event->next = NULL;
  event->generation = event_generation;
  event->type = type;
  event->code = code;
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

// PacketsToConnection answers handshakes, acknowledges and resets flows and serves
// fake DNS on the device itself, so only relayed payload shows the server path works.
static bool carriesRemotePayload(const uint8_t *packet, size_t length) {
  if (length < 20 || (packet[0] >> 4) != 4) {
    return false;
  }
  const size_t ihl = (size_t)(packet[0] & 0x0f) * 4;
  const size_t stated = ((size_t)packet[2] << 8) | packet[3];
  const size_t total = length < stated ? length : stated;
  if (ihl < 20 || total < ihl + 8) {
    return false;
  }
  if (packet[9] == 6) {
    if (total < ihl + 20) {
      return false;
    }
    const size_t header = (size_t)(packet[ihl + 12] >> 4) * 4;
    return header >= 20 && total > ihl + header;
  }
  return packet[9] == 17 && (((uint16_t)packet[ihl] << 8) | packet[ihl + 1]) != 53;
}

static bool matchesProbeFlow(const uint8_t *packet, size_t length) {
  if (atomic_load_explicit(&probe_flow_count, memory_order_relaxed) == 0 || length < 28 || (packet[0] >> 4) != 4) {
    return false;
  }
  const size_t ihl = (size_t)(packet[0] & 0x0f) * 4;
  if (ihl < 20 || length < ihl + 4) {
    return false;
  }
  const uint16_t destination_port = ((uint16_t)packet[ihl + 2] << 8) | packet[ihl + 3];
  bool found = false;
  pthread_mutex_lock(&probe_lock);
  const int count = atomic_load(&probe_flow_count);
  for (int index = 0; index < count && !found; index++) {
    found = probe_flows[index].protocol == packet[9] && probe_flows[index].destination_port == destination_port &&
            memcmp(probe_flows[index].source, packet + 12, 4) == 0;
  }
  pthread_mutex_unlock(&probe_lock);
  return found;
}

static void onPacket(void *context, const uint8_t *packet, size_t length) {
  if (carriesRemotePayload(packet, length)) {
    atomic_store_explicit(&last_payload_ms, uptimeMs(), memory_order_relaxed);
  }
  // The app's own probes must not reach the kernel, which would answer them with a reset.
  if (matchesProbeFlow(packet, length)) {
    postEvent((uint32_t)(uintptr_t)context, kEventProbePacket, 0, packet, length);
    return;
  }
  const int fd = atomic_load_explicit(&tun_fd, memory_order_relaxed);
  if (fd >= 0) {
    // A full TUN queue is a lost packet to the apps behind it, and TCP recovers those.
    (void)write(fd, packet, length);
  }
}

// Debug on a long session writes a lot, so past 2 MB keep the last 512 KB, as ConnectionLog does when it opens the file.
static void capLog(int fd) {
  if (pthread_mutex_trylock(&log_cap_lock) != 0) {
    return;
  }
  uint8_t *tail = malloc(kLogKeepBytes);
  const off_t size = lseek(fd, 0, SEEK_END);
  if (tail != NULL && size > kLogKeepBytes) {
    const ssize_t count = pread(fd, tail, kLogKeepBytes, size - kLogKeepBytes);
    if (count > 0 && ftruncate(fd, 0) == 0) {
      (void)write(fd, tail, (size_t)count);
      atomic_store(&log_bytes, count);
    }
  }
  free(tail);
  pthread_mutex_unlock(&log_cap_lock);
}

static void writeLogLine(const char *message, size_t length) {
  const int fd = atomic_load(&log_fd);
  if (fd < 0) {
    return;
  }
  (void)write(fd, message, length);
  if (length == 0 || message[length - 1] != '\n') {
    (void)write(fd, "\n", 1);
  }
  if (atomic_fetch_add(&log_bytes, (long long)length + 1) > kLogCapBytes) {
    capLog(fd);
  }
}

// WaterWall prints startup errors to stderr, which is /dev/null in an app. Only while it starts: stderr is the whole process's.
static void captureStartupErrors(bool capture) {
  static int normal = -1;
  if (normal < 0) {
    normal = dup(STDERR_FILENO);
  }
  const int fd = atomic_load(&log_fd);
  if (capture && fd >= 0) {
    dup2(fd, STDERR_FILENO);
  } else if (!capture && normal >= 0) {
    dup2(normal, STDERR_FILENO);
  }
}

static void onLog(void *context, int level, const char *message, size_t length) {
  (void)context;
  if (message == NULL) {
    return;
  }
  // Normal keeps errors and known flow events, as on iOS: every TLS line's normal end is a warning, for example.
  if (level < 4 && atomic_load(&log_level) < 1) {
    static const char *const prefixes[] = {
        "VmessClient:", "TcpConnector: received close", "PacketsToConnection: closing flow",
        "PacketsToConnection: closing TCP flow",
    };
    bool keep = false;
    for (size_t index = 0; index < sizeof(prefixes) / sizeof(prefixes[0]) && !keep; index++) {
      keep = strstr(message, prefixes[index]) != NULL;
    }
    if (!keep) {
      return;
    }
  }
  writeLogLine(message, length);
}

static void onReady(void *context) {
  captureStartupErrors(false);
  postEvent((uint32_t)(uintptr_t)context, kEventReady, 0, NULL, 0);
}

static void onFailure(void *context, int code, const char *message) {
  captureStartupErrors(false);
  // The runtime is gone, and with it what submitting needs.
  atomic_store(&accepting, false);
  postEvent((uint32_t)(uintptr_t)context, kEventFailure, code, message, strlen(message));
}

static int submit(const void *packet, size_t length) {
  pthread_mutex_lock(&bridge_lock);
  const int result = bridge == NULL ? -ENOTCONN : SRPWaterWallBridgeSubmitPacket(bridge, packet, length);
  pthread_mutex_unlock(&bridge_lock);
  return result;
}

static void dropHeldPackets(void) {
  while (held_head != NULL) {
    held_packet_t *next = held_head->next;
    free(held_head);
    held_head = next;
  }
  held_tail = NULL;
  held_bytes = 0;
}

// Submits what waits, in order. False when the runtime cannot take more yet.
static bool feedHeldPackets(void) {
  while (held_head != NULL) {
    const int result = submit(held_head->bytes, held_head->length);
    if (result != 0 && result != -EINVAL) {
      if (result == -ENOTCONN && !atomic_exchange(&channel_stop_reported, true)) {
        postEvent(generation, kEventChannelStopped, result, NULL, 0);
      }
      return false;
    }
    held_packet_t *done = held_head;
    held_head = done->next;
    held_bytes -= done->length;
    free(done);
  }
  held_tail = NULL;
  return true;
}

static void holdPacket(const uint8_t *bytes, size_t length) {
  held_packet_t *packet = malloc(sizeof(*packet) + length);
  if (packet == NULL) {
    return;
  }
  packet->next = NULL;
  packet->length = length;
  memcpy(packet->bytes, bytes, length);
  if (held_tail != NULL) {
    held_tail->next = packet;
  } else {
    held_head = packet;
  }
  held_tail = packet;
  held_bytes += length;
}

static void *readTun(void *unused) {
  (void)unused;
  static uint8_t packet[65535];
  const int fd = atomic_load(&tun_fd);
  while (!atomic_load(&reader_stop)) {
    // While the runtime restarts the kernel queues packets, and those of the old runtime's flows are of no use to the new one.
    const bool open = atomic_load(&accepting);
    if (!open) {
      dropHeldPackets();
    }
    const bool fed = !open || feedHeldPackets();
    // Android's TUN queue drops what passes its 500 packets. Inside a raw IP chain that is a lost stretch for the sender to repair
    // through the server's lwIP, which takes a second for every four segments, so read ahead of a busy runtime instead.
    // shortcut: 8 MiB holds two full TCP windows and more uploads at once still lose packets; a server that acknowledges batches would end that.
    struct pollfd ready = {.fd = fd, .events = open && held_bytes < kReadAheadBytes ? POLLIN : 0};
    const int count = poll(&ready, 1, !open ? 50 : fed ? 200 : 1);
    if (count <= 0) {
      continue;
    }
    if (!(ready.revents & POLLIN)) {
      return NULL;
    }
    const ssize_t length = read(fd, packet, sizeof(packet));
    if (length <= 0) {
      if (length == 0 || (errno != EAGAIN && errno != EINTR)) {
        // The tunnel was taken away; WaterWallClient learns it from Android.
        return NULL;
      }
      continue;
    }
    // The tunnel carries IPv4 only, and Android still sends it a little IPv6 of its own.
    if ((packet[0] >> 4) != 4) {
      continue;
    }
    if (held_head != NULL) {
      holdPacket(packet, (size_t)length);
      continue;
    }
    const int result = submit(packet, (size_t)length);
    if (result != 0 && result != -EINVAL) {
      holdPacket(packet, (size_t)length);
    }
  }
  return NULL;
}

static void stopReader(void) {
  if (reader_running) {
    atomic_store(&reader_stop, true);
    pthread_join(reader, NULL);
    reader_running = false;
    dropHeldPackets();
  }
}

// Android finds these by name, so no header carries their prototypes.
JNIEXPORT jint JNICALL Java_tr_com_srp_vpn_WaterWall_start(JNIEnv *, jclass, jbyteArray, jbyteArray);
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WaterWall_stop(JNIEnv *, jclass);
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WaterWall_attachTun(JNIEnv *, jclass, jint);
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WaterWall_detachTun(JNIEnv *, jclass);
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WaterWall_setAccepting(JNIEnv *, jclass, jboolean);
JNIEXPORT jint JNICALL Java_tr_com_srp_vpn_WaterWall_submit(JNIEnv *, jclass, jbyteArray);
JNIEXPORT jbyteArray JNICALL Java_tr_com_srp_vpn_WaterWall_nextEvent(JNIEnv *, jclass);
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WaterWall_setProbeFlows(JNIEnv *, jclass, jintArray);
JNIEXPORT jlong JNICALL Java_tr_com_srp_vpn_WaterWall_lastPayloadAgeMs(JNIEnv *, jclass);
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WaterWall_setLog(JNIEnv *, jclass, jstring, jint);
JNIEXPORT jlongArray JNICALL Java_tr_com_srp_vpn_WaterWall_readLinkCounters(JNIEnv *, jclass);
JNIEXPORT jstring JNICALL Java_tr_com_srp_vpn_WaterWall_geoIpError(JNIEnv *, jclass, jstring);
JNIEXPORT jobjectArray JNICALL Java_tr_com_srp_vpn_WaterWall_geoIpInfo(JNIEnv *, jclass, jstring);
JNIEXPORT jbyteArray JNICALL Java_tr_com_srp_vpn_WaterWall_x25519PublicKey(JNIEnv *, jclass, jbyteArray);

static char *copyString(JNIEnv *env, jbyteArray bytes) {
  const jsize length = (*env)->GetArrayLength(env, bytes);
  char *copy = malloc((size_t)length + 1);
  if (copy != NULL) {
    (*env)->GetByteArrayRegion(env, bytes, 0, length, (jbyte *)copy);
    copy[length] = '\0';
  }
  return copy;
}

// The generation that tags this runtime's events, or 0 when it did not start.
JNIEXPORT jint JNICALL Java_tr_com_srp_vpn_WaterWall_start(JNIEnv *env, jclass cls, jbyteArray core_json, jbyteArray nodes_json) {
  (void)cls;
  char *core = copyString(env, core_json);
  char *nodes = copyString(env, nodes_json);
  if (core == NULL || nodes == NULL) {
    free(core);
    free(nodes);
    return 0;
  }
  pthread_mutex_lock(&bridge_lock);
  const uint32_t started_generation = ++generation;
  const SRPWaterWallConfig config = {.core_json = core, .nodes_json = nodes};
  const SRPWaterWallCallbacks callbacks = {.packet = onPacket,
                                           .log = onLog,
                                           .ready = onReady,
                                           .failure = onFailure,
                                           .context = (void *)(uintptr_t)started_generation};
  atomic_store(&last_payload_ms, 0);
  atomic_store(&channel_stop_reported, false);
  captureStartupErrors(true);
  SRPWaterWallBridge *runtime = SRPWaterWallBridgeStart(&config, &callbacks);
  // One that is still running stays stoppable when another start is refused.
  if (runtime != NULL) {
    bridge = runtime;
  }
  pthread_mutex_unlock(&bridge_lock);
  free(core);
  free(nodes);
  return runtime != NULL ? (jint)started_generation : 0;
}

JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WaterWall_stop(JNIEnv *env, jclass cls) {
  (void)env;
  (void)cls;
  atomic_store(&accepting, false);
  pthread_mutex_lock(&bridge_lock);
  SRPWaterWallBridge *stopping = bridge;
  bridge = NULL;
  pthread_mutex_unlock(&bridge_lock);
  if (stopping != NULL) {
    const int result = SRPWaterWallBridgeStop(stopping);
    if (result != 0) {
      char line[64];
      const int length = snprintf(line, sizeof(line), "WaterWall: stop returned %d", result);
      writeLogLine(line, (size_t)length);
    }
  }
}

JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WaterWall_attachTun(JNIEnv *env, jclass cls, jint fd) {
  (void)env;
  (void)cls;
  stopReader();
  atomic_store(&tun_fd, fd);
  atomic_store(&reader_stop, false);
  reader_running = pthread_create(&reader, NULL, readTun, NULL) == 0;
}

JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WaterWall_detachTun(JNIEnv *env, jclass cls) {
  (void)env;
  (void)cls;
  stopReader();
  atomic_store(&tun_fd, -1);
}

JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WaterWall_setAccepting(JNIEnv *env, jclass cls, jboolean value) {
  (void)env;
  (void)cls;
  if (value) {
    atomic_store(&channel_stop_reported, false);
  }
  atomic_store(&accepting, value);
}

JNIEXPORT jint JNICALL Java_tr_com_srp_vpn_WaterWall_submit(JNIEnv *env, jclass cls, jbyteArray packet) {
  (void)cls;
  const jsize length = (*env)->GetArrayLength(env, packet);
  jbyte *bytes = (*env)->GetByteArrayElements(env, packet, NULL);
  const int result = submit(bytes, (size_t)length);
  (*env)->ReleaseByteArrayElements(env, packet, bytes, JNI_ABORT);
  return result;
}

// Blocks for the next event: [type, generation (4 bytes), code (4 bytes), payload...].
JNIEXPORT jbyteArray JNICALL Java_tr_com_srp_vpn_WaterWall_nextEvent(JNIEnv *env, jclass cls) {
  (void)cls;
  pthread_mutex_lock(&event_lock);
  while (event_head == NULL) {
    pthread_cond_wait(&event_ready, &event_lock);
  }
  event_t *event = event_head;
  event_head = event->next;
  if (event_head == NULL) {
    event_tail = NULL;
  }
  pthread_mutex_unlock(&event_lock);
  uint8_t header[9] = {event->type};
  memcpy(header + 1, &event->generation, 4);
  memcpy(header + 5, &event->code, 4);
  jbyteArray result = (*env)->NewByteArray(env, (jsize)(sizeof(header) + event->length));
  (*env)->SetByteArrayRegion(env, result, 0, sizeof(header), (const jbyte *)header);
  (*env)->SetByteArrayRegion(env, result, sizeof(header), (jsize)event->length, (const jbyte *)event->bytes);
  free(event);
  return result;
}

// Triples of protocol, IPv4 source (network order in the int's bytes, high first) and destination port.
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WaterWall_setProbeFlows(JNIEnv *env, jclass cls, jintArray flows) {
  (void)cls;
  const jsize values = (*env)->GetArrayLength(env, flows);
  const int count = values / 3 > kMaxProbeFlows ? kMaxProbeFlows : values / 3;
  jint *items = (*env)->GetIntArrayElements(env, flows, NULL);
  pthread_mutex_lock(&probe_lock);
  for (int index = 0; index < count; index++) {
    probe_flows[index].protocol = items[index * 3];
    const uint32_t source = (uint32_t)items[index * 3 + 1];
    probe_flows[index].source[0] = (uint8_t)(source >> 24);
    probe_flows[index].source[1] = (uint8_t)(source >> 16);
    probe_flows[index].source[2] = (uint8_t)(source >> 8);
    probe_flows[index].source[3] = (uint8_t)source;
    probe_flows[index].destination_port = (uint16_t)items[index * 3 + 2];
  }
  atomic_store(&probe_flow_count, count);
  pthread_mutex_unlock(&probe_lock);
  (*env)->ReleaseIntArrayElements(env, flows, items, JNI_ABORT);
}

// Milliseconds since relayed payload last arrived, or -1 when none has since the runtime started.
JNIEXPORT jlong JNICALL Java_tr_com_srp_vpn_WaterWall_lastPayloadAgeMs(JNIEnv *env, jclass cls) {
  (void)env;
  (void)cls;
  const long long last = atomic_load_explicit(&last_payload_ms, memory_order_relaxed);
  return last == 0 ? -1 : uptimeMs() - last;
}

JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WaterWall_setLog(JNIEnv *env, jclass cls, jstring path, jint level) {
  (void)cls;
  const char *chars = (*env)->GetStringUTFChars(env, path, NULL);
  const int fd = open(chars, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
  (*env)->ReleaseStringUTFChars(env, path, chars);
  atomic_store(&log_level, level);
  const int previous = atomic_exchange(&log_fd, fd);
  if (previous >= 0) {
    close(previous);
  }
  if (fd >= 0) {
    atomic_store(&log_bytes, lseek(fd, 0, SEEK_END));
  }
}

JNIEXPORT jlongArray JNICALL Java_tr_com_srp_vpn_WaterWall_readLinkCounters(JNIEnv *env, jclass cls) {
  (void)cls;
  SRPWaterWallLinkCounters counters = {0};
  SRPWaterWallBridgeReadLinkCounters(&counters);
  const jlong values[6] = {(jlong)counters.tx_packets,          (jlong)counters.retransmitted_packets,
                           (jlong)counters.rx_bytes,            (jlong)counters.timed_out_connections,
                           (jlong)counters.max_srtt_ms,         (jlong)counters.max_rto_ms};
  jlongArray result = (*env)->NewLongArray(env, 6);
  if (result != NULL) {
    (*env)->SetLongArrayRegion(env, result, 0, 6, values);
  }
  return result;
}

static bool geoIpCountryEntryIsValid(MMDB_entry_s *entry) {
  static const char *const names[] = {"country", "registered_country"};
  for (size_t index = 0; index < 2; index++) {
    MMDB_entry_data_s data = {0};
    const int status = MMDB_get_value(entry, &data, names[index], "iso_code", NULL);
    if (status == MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {
      continue;
    }
    return status == MMDB_SUCCESS && data.has_data && data.type == MMDB_DATA_TYPE_UTF8_STRING && data.data_size == 2;
  }
  return false;
}

// Why the file is not a usable country database, or null when it is.
JNIEXPORT jstring JNICALL Java_tr_com_srp_vpn_WaterWall_geoIpError(JNIEnv *env, jclass cls, jstring path) {
  (void)cls;
  const char *chars = (*env)->GetStringUTFChars(env, path, NULL);
  char failure[256] = {0};
  MMDB_s database;
  const int status = MMDB_open(chars, MMDB_MODE_MMAP, &database);
  (*env)->ReleaseStringUTFChars(env, path, chars);
  if (status != MMDB_SUCCESS) {
    snprintf(failure, sizeof(failure), "The file is not a valid MaxMind database: %s", MMDB_strerror(status));
    return (*env)->NewStringUTF(env, failure);
  }
  const char *type = database.metadata.database_type;
  if (type == NULL || strcasestr(type, "Country") == NULL ||
      (database.metadata.ip_version != 4 && database.metadata.ip_version != 6)) {
    snprintf(failure, sizeof(failure), "The database type '%s' is unsupported. Use a GeoIP2 or GeoLite2 Country MMDB.",
             type != NULL ? type : "unknown");
  } else {
    int address_error = 0;
    int lookup_error = MMDB_SUCCESS;
    MMDB_lookup_result_s result = MMDB_lookup_string(&database, "1.1.1.1", &address_error, &lookup_error);
    if (address_error != 0 || lookup_error != MMDB_SUCCESS) {
      snprintf(failure, sizeof(failure), "The database lookup tree could not be read.");
    } else if (result.found_entry && !geoIpCountryEntryIsValid(&result.entry)) {
      snprintf(failure, sizeof(failure), "The database does not contain valid two-letter country entries.");
    }
  }
  MMDB_close(&database);
  return failure[0] != 0 ? (*env)->NewStringUTF(env, failure) : NULL;
}

// The database's type and file size in bytes, or null.
JNIEXPORT jobjectArray JNICALL Java_tr_com_srp_vpn_WaterWall_geoIpInfo(JNIEnv *env, jclass cls, jstring path) {
  (void)cls;
  const char *chars = (*env)->GetStringUTFChars(env, path, NULL);
  MMDB_s database;
  const int status = MMDB_open(chars, MMDB_MODE_MMAP, &database);
  (*env)->ReleaseStringUTFChars(env, path, chars);
  if (status != MMDB_SUCCESS) {
    return NULL;
  }
  char bytes[32];
  snprintf(bytes, sizeof(bytes), "%lld", (long long)database.file_size);
  jobjectArray result = (*env)->NewObjectArray(env, 2, (*env)->FindClass(env, "java/lang/String"), NULL);
  if (result != NULL) {
    (*env)->SetObjectArrayElement(env, result, 0, (*env)->NewStringUTF(env, database.metadata.database_type));
    (*env)->SetObjectArrayElement(env, result, 1, (*env)->NewStringUTF(env, bytes));
  }
  MMDB_close(&database);
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_tr_com_srp_vpn_WaterWall_x25519PublicKey(JNIEnv *env, jclass cls, jbyteArray private_key) {
  (void)cls;
  if ((*env)->GetArrayLength(env, private_key) != 32) {
    return NULL;
  }
  unsigned char secret[32];
  unsigned char public_key[32];
  (*env)->GetByteArrayRegion(env, private_key, 0, 32, (jbyte *)secret);
  const int status = crypto_scalarmult_curve25519_base(public_key, secret);
  sodium_memzero(secret, sizeof(secret));
  if (status != 0) {
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, 32);
  if (result != NULL) {
    (*env)->SetByteArrayRegion(env, result, 0, 32, (const jbyte *)public_key);
  }
  return result;
}
