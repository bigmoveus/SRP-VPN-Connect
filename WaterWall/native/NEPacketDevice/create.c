#include "NEPacketDevice/structure.h"

#include "loggers/network_logger.h"

nepacketdevice_tstate_t *srpNEPacketDeviceState = NULL;

bool srpNEPacketDeviceConfigure(SRPNEPacketWriteCallback packet,
                                SRPNEPacketLogCallback log, void *context) {
  if (srpNEPacketDeviceState != NULL) {
    return false;
  }
  srpNEPacketDeviceState = memoryAllocateZero(sizeof(nepacketdevice_tstate_t));
  srpNEPacketDeviceState->packet_callback = packet;
  srpNEPacketDeviceState->log_callback = log;
  srpNEPacketDeviceState->callback_context = context;
  return true;
}

void srpNEPacketDeviceClose(void) {
  nepacketdevice_tstate_t *state = srpNEPacketDeviceState;
  if (state == NULL) {
    return;
  }
  if (state->mutex_initialized) {
    mutexLock(&state->ingress_mutex);
    state->ingress_open = false;
    state->ready = false;
    mutexUnlock(&state->ingress_mutex);
  }
  if (state->owner == NULL) {
    memoryFree(state);
    srpNEPacketDeviceState = NULL;
  }
}

tunnel_t *nepacketdeviceTunnelCreate(node_t *node) {
  tunnel_t *t = packettunnelCreate(node, sizeof(nepacketdevice_tstate_t), 0);
  if (t == NULL) {
    return NULL;
  }
  const packet_lifecycle_anchor_direction_t direction =
      node->next != NULL ? kPacketLifecycleAnchorPublishUpstream
                         : kPacketLifecycleAnchorPublishDownstream;
  if (srpNEPacketDeviceState == NULL || srpNEPacketDeviceState->owner != NULL ||
      !packettunnelConfigureLifecycleAnchor(
          t, "NEPacketDevice", nepacketdeviceTunnelWritePayload, direction)) {
    tunnelDestroy(t);
    return NULL;
  }

  nepacketdevice_tstate_t configured = *srpNEPacketDeviceState;
  memoryFree(srpNEPacketDeviceState);

  nepacketdevice_tstate_t *state = tunnelGetState(t);
  *state = configured;
  state->owner = t;
  srpNEPacketDeviceState = state;
  if (!mutexTryInit(&state->ingress_mutex)) {
    srpNEPacketDeviceState = NULL;
    tunnelDestroy(t);
    return NULL;
  }
  state->mutex_initialized = true;
  state->ingress_open = true;

  t->onStart = nepacketdeviceTunnelOnStart;
  t->onQuiesceRequest = nepacketdeviceTunnelOnQuiesceRequest;
  t->onWorkerQuiesce = nepacketdeviceTunnelOnWorkerQuiesce;
  t->onStop = nepacketdeviceTunnelOnStop;
  t->onDestroy = nepacketdeviceTunnelDestroy;
  t->fnPauseD = nepacketdeviceTunnelDownstreamPause;
  t->fnResumeD = nepacketdeviceTunnelDownstreamResume;
  return t;
}

void nepacketdeviceTunnelDestroy(tunnel_t *t,
                                 const ww_lifecycle_context_t *context) {
  discard context;
  nepacketdevice_tstate_t *state = tunnelGetState(t);
  srpNEPacketDeviceState = NULL;
  if (state->mutex_initialized) {
    mutexDestroy(&state->ingress_mutex);
  }
  tunnelDestroy(t);
}
