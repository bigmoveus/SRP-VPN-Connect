#include "SRPWaterWallBridge.h"

#include "SRPNEPacketDevice.h"
#include "hosted_runtime.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

struct SRPWaterWallBridge {
  pthread_t thread;
  SRPWaterWallCallbacks callbacks;
  char *core_json;
  char *nodes_json;
  atomic_bool stop_requested;
  atomic_bool ready;
  atomic_bool runtime_exited;
};

static pthread_mutex_t srpBridgeMutex = PTHREAD_MUTEX_INITIALIZER;
static SRPWaterWallBridge *srpBridgeActive = NULL;

static char *srpBridgeDuplicate(const char *value) {
  if (value == NULL) {
    return NULL;
  }
  const size_t length = strlen(value) + 1U;
  char *copy = malloc(length);
  if (copy != NULL) {
    memcpy(copy, value, length);
  }
  return copy;
}

static bool srpBridgeStopRequested(void) {
  return srpBridgeActive != NULL &&
         atomic_load(&srpBridgeActive->stop_requested);
}

static void srpBridgePacket(void *context, const uint8_t *packet,
                            size_t length) {
  SRPWaterWallBridge *bridge = context;
  if (bridge->callbacks.packet != NULL &&
      !atomic_load(&bridge->stop_requested)) {
    bridge->callbacks.packet(bridge->callbacks.context, packet, length);
  }
}

static void srpBridgeLog(int level, const char *message, int length) {
  SRPWaterWallBridge *bridge = srpBridgeActive;
  if (bridge != NULL && bridge->callbacks.log != NULL && message != NULL &&
      length >= 0) {
    bridge->callbacks.log(bridge->callbacks.context, level, message,
                          (size_t)length);
  }
}

static void srpBridgeReady(void) {
  SRPWaterWallBridge *bridge = srpBridgeActive;
  if (bridge != NULL && !atomic_load(&bridge->stop_requested)) {
    atomic_store(&bridge->ready, true);
    if (bridge->callbacks.ready != NULL) {
      bridge->callbacks.ready(bridge->callbacks.context);
    }
  }
}

static void *srpBridgeMain(void *context) {
  SRPWaterWallBridge *bridge = context;
  const int result = srpWaterWallHostedRun(
      bridge->core_json, bridge->nodes_json, srpBridgeReady,
      srpBridgeStopRequested, srpBridgeLog);
  atomic_store(&bridge->runtime_exited, true);
  if (!atomic_load(&bridge->stop_requested) && bridge->callbacks.failure != NULL) {
    bridge->callbacks.failure(bridge->callbacks.context, result,
                              result == 0 ? "WaterWall runtime stopped" :
                                            "WaterWall runtime stopped with an error");
  }
  return NULL;
}

SRPWaterWallBridge *
SRPWaterWallBridgeStart(const SRPWaterWallConfig *config,
                        const SRPWaterWallCallbacks *callbacks) {
  if (config == NULL || callbacks == NULL || callbacks->packet == NULL ||
      config->nodes_json == NULL) {
    return NULL;
  }

  pthread_mutex_lock(&srpBridgeMutex);
  if (srpBridgeActive != NULL) {
    pthread_mutex_unlock(&srpBridgeMutex);
    return NULL;
  }

  SRPWaterWallBridge *bridge = calloc(1, sizeof(*bridge));
  if (bridge == NULL) {
    pthread_mutex_unlock(&srpBridgeMutex);
    return NULL;
  }
  bridge->callbacks = *callbacks;
  bridge->core_json = srpBridgeDuplicate(
      config->core_json == NULL ? "{\"configs\":[\"hosted-nodes.json\"]}"
                                : config->core_json);
  bridge->nodes_json = srpBridgeDuplicate(config->nodes_json);
  if (bridge->core_json == NULL || bridge->nodes_json == NULL ||
      !srpNEPacketDeviceConfigure(srpBridgePacket, NULL, bridge)) {
    free(bridge->core_json);
    free(bridge->nodes_json);
    free(bridge);
    pthread_mutex_unlock(&srpBridgeMutex);
    return NULL;
  }

  srpBridgeActive = bridge;
  const int result =
      pthread_create(&bridge->thread, NULL, srpBridgeMain, bridge);
  pthread_mutex_unlock(&srpBridgeMutex);
  if (result != 0) {
    pthread_mutex_lock(&srpBridgeMutex);
    srpBridgeActive = NULL;
    pthread_mutex_unlock(&srpBridgeMutex);
    srpNEPacketDeviceClose();
    free(bridge->core_json);
    free(bridge->nodes_json);
    free(bridge);
    return NULL;
  }
  return bridge;
}

int SRPWaterWallBridgeSubmitPacket(SRPWaterWallBridge *bridge,
                                   const void *packet, size_t length) {
  if (bridge == NULL || packet == NULL) {
    return -EINVAL;
  }
  if (atomic_load(&bridge->stop_requested) || !atomic_load(&bridge->ready)) {
    return -ENOTCONN;
  }
  return srpNEPacketDeviceSubmit(packet, length);
}

int SRPWaterWallBridgeStop(SRPWaterWallBridge *bridge) {
  if (bridge == NULL) {
    return -EINVAL;
  }
  if (pthread_equal(pthread_self(), bridge->thread) != 0) {
    return -EDEADLK;
  }

  pthread_mutex_lock(&srpBridgeMutex);
  if (srpBridgeActive != bridge) {
    pthread_mutex_unlock(&srpBridgeMutex);
    return -EINVAL;
  }
  atomic_store(&bridge->stop_requested, true);
  srpNEPacketDeviceClose();
  if (!atomic_load(&bridge->runtime_exited)) {
    (void)requestProgramShutdown(0);
  }
  pthread_mutex_unlock(&srpBridgeMutex);

  const int result = pthread_join(bridge->thread, NULL);
  if (result != 0) {
    return -result;
  }

  pthread_mutex_lock(&srpBridgeMutex);
  srpBridgeActive = NULL;
  pthread_mutex_unlock(&srpBridgeMutex);
  free(bridge->core_json);
  free(bridge->nodes_json);
  free(bridge);
  return 0;
}
