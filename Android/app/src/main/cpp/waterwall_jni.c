#include "SRPWaterWallBridge.h"

#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

// One session per process, as the bridge allows. start, await and stop are the only ways in.
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static bool active;
static bool finished;
static int exit_code;

static SRPWaterWallBridge *bridge;
static pthread_t reader;
static atomic_bool reader_stop;
static int tun_fd = -1;
static int log_fd = -1;

static void finish(int code) {
  pthread_mutex_lock(&lock);
  if (active) {
    if (!finished) {
      exit_code = code;
    }
    finished = true;
    pthread_cond_signal(&changed);
  }
  pthread_mutex_unlock(&lock);
}

static void writeLog(int level, const char *message, size_t length) {
  (void)write(log_fd, message, length);
  if (length == 0 || message[length - 1] != '\n') {
    (void)write(log_fd, "\n", 1);
  }
  __android_log_print(level >= 4 ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO, "WaterWall", "%.*s", (int)length, message);
}

static void onLog(void *context, int level, const char *message, size_t length) {
  (void)context;
  writeLog(level, message, length);
}

static void onFailure(void *context, int code, const char *message) {
  (void)context;
  writeLog(4, message, strlen(message));
  finish(code == 0 ? 1 : code);
}

static void onPacket(void *context, const uint8_t *packet, size_t length) {
  (void)context;
  // A full TUN queue is a lost packet to the apps behind it, and TCP recovers those.
  (void)write(tun_fd, packet, length);
}

static void *readTun(void *unused) {
  (void)unused;
  static uint8_t packet[65535];
  struct pollfd ready = {.fd = tun_fd, .events = POLLIN};
  while (!atomic_load(&reader_stop)) {
    if (poll(&ready, 1, 200) <= 0) {
      continue;
    }
    const ssize_t length = read(tun_fd, packet, sizeof(packet));
    if (length <= 0) {
      if (length == 0 || (errno != EAGAIN && errno != EINTR)) {
        finish(length == 0 ? 1 : errno);
        return NULL;
      }
      continue;
    }
    // Hold the packet while the runtime starts or its queue is full: the kernel queues the next ones.
    int result;
    while ((result = SRPWaterWallBridgeSubmitPacket(bridge, packet, (size_t)length)) == -EAGAIN ||
           result == -ENOTCONN) {
      if (atomic_load(&reader_stop)) {
        return NULL;
      }
      usleep(1000);
    }
  }
  return NULL;
}

// Android finds these by name, so no header carries their prototypes.
JNIEXPORT jboolean JNICALL Java_tr_com_srp_vpn_WaterWall_start(JNIEnv *, jclass, jint, jstring, jstring, jstring);
JNIEXPORT jint JNICALL Java_tr_com_srp_vpn_WaterWall_await(JNIEnv *, jclass);
JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WaterWall_stop(JNIEnv *, jclass);

// Runs on the service's main thread, so a stop that follows cannot find the session missing.
JNIEXPORT jboolean JNICALL Java_tr_com_srp_vpn_WaterWall_start(JNIEnv *env, jclass cls, jint fd, jstring core_json,
                                                               jstring nodes_json, jstring log_path) {
  (void)cls;
  // shortcut: the log only grows until the next connect, rotate it when the real log screen is ported.
  const char *path = (*env)->GetStringUTFChars(env, log_path, NULL);
  log_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND | O_CLOEXEC, 0600);
  (*env)->ReleaseStringUTFChars(env, log_path, path);
  if (log_fd < 0) {
    return JNI_FALSE;
  }
  // WaterWall prints startup errors to stderr, which is /dev/null in an app.
  dup2(log_fd, STDERR_FILENO);
  tun_fd = fd;
  atomic_store(&reader_stop, false);
  // Before the bridge starts, so that a failure on its first breath is not lost.
  pthread_mutex_lock(&lock);
  active = true;
  finished = false;
  exit_code = 0;
  pthread_mutex_unlock(&lock);

  const char *core = (*env)->GetStringUTFChars(env, core_json, NULL);
  const char *nodes = (*env)->GetStringUTFChars(env, nodes_json, NULL);
  const SRPWaterWallConfig config = {.core_json = core, .nodes_json = nodes};
  const SRPWaterWallCallbacks callbacks = {.packet = onPacket, .log = onLog, .failure = onFailure};
  bridge = SRPWaterWallBridgeStart(&config, &callbacks);
  (*env)->ReleaseStringUTFChars(env, core_json, core);
  (*env)->ReleaseStringUTFChars(env, nodes_json, nodes);
  if (bridge != NULL && pthread_create(&reader, NULL, readTun, NULL) == 0) {
    return JNI_TRUE;
  }

  pthread_mutex_lock(&lock);
  active = false;
  pthread_mutex_unlock(&lock);
  if (bridge != NULL) {
    SRPWaterWallBridgeStop(bridge);
  }
  close(log_fd);
  return JNI_FALSE;
}

// Blocks until stop or a runtime failure, then tears the session down and returns the exit code.
JNIEXPORT jint JNICALL Java_tr_com_srp_vpn_WaterWall_await(JNIEnv *env, jclass cls) {
  (void)env;
  (void)cls;
  pthread_mutex_lock(&lock);
  while (!finished) {
    pthread_cond_wait(&changed, &lock);
  }
  const int code = exit_code;
  pthread_mutex_unlock(&lock);

  atomic_store(&reader_stop, true);
  pthread_join(reader, NULL);
  const int stopped = SRPWaterWallBridgeStop(bridge);

  pthread_mutex_lock(&lock);
  active = false;
  pthread_mutex_unlock(&lock);
  close(log_fd);
  return code != 0 ? code : -stopped;
}

JNIEXPORT void JNICALL Java_tr_com_srp_vpn_WaterWall_stop(JNIEnv *env, jclass cls) {
  (void)env;
  (void)cls;
  finish(0);
}
