#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SRPWaterWallBridge SRPWaterWallBridge;

typedef struct SRPWaterWallConfig {
  const char *core_json;
  const char *nodes_json;
} SRPWaterWallConfig;

typedef void (*SRPWaterWallPacketCallback)(void *context, const uint8_t *packet,
                                           size_t length);
typedef void (*SRPWaterWallLogCallback)(void *context, int level,
                                        const char *message, size_t length);
typedef void (*SRPWaterWallReadyCallback)(void *context);
typedef void (*SRPWaterWallFailureCallback)(void *context, int code,
                                            const char *message);

typedef struct SRPWaterWallCallbacks {
  SRPWaterWallPacketCallback packet;
  SRPWaterWallLogCallback log;
  SRPWaterWallReadyCallback ready;
  SRPWaterWallFailureCallback failure;
  void *context;
} SRPWaterWallCallbacks;

/*
 * Start owns copies of both JSON strings and the callback structure. context is
 * borrowed until a successful Stop. ready/failure/log/packet run on WaterWall's
 * worker thread. packet bytes are borrowed only for the callback duration.
 * One process-wide runtime is allowed; a second concurrent Start returns NULL.
 */
SRPWaterWallBridge *
SRPWaterWallBridgeStart(const SRPWaterWallConfig *config,
                        const SRPWaterWallCallbacks *callbacks);

/* Submit copies the complete IP packet before returning. Zero means accepted;
 * -EINVAL is invalid input, -EAGAIN is a full/paused queue, and -ENOTCONN means
 * the runtime is not ready or is stopping. Calls are serialized internally.
 */
int SRPWaterWallBridgeSubmitPacket(SRPWaterWallBridge *bridge,
                                   const void *packet, size_t length);

/*
 * Stop is idempotent only after a previous successful Stop freed the handle.
 * It closes admission, joins the runtime, and frees bridge. It returns zero on
 * success or -EDEADLK when called from a WaterWall callback; in that case the
 * handle remains valid and Stop must be retried from another thread.
 */
int SRPWaterWallBridgeStop(SRPWaterWallBridge *bridge);

#ifdef __cplusplus
}
#endif
