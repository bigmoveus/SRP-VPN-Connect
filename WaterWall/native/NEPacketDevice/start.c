#include "NEPacketDevice/structure.h"

#include "loggers/network_logger.h"

void nepacketdeviceTunnelOnStart(tunnel_t *t) {
  nepacketdevice_tstate_t *state = tunnelGetState(t);
  if (getWorkersCount() != 1) {
    LOGF("NEPacketDevice: hosted mode requires exactly one worker");
    startupFailureRecord(1);
    return;
  }
  state->lifecycle_anchor.direction =
      t->next != NULL ? kPacketLifecycleAnchorPublishUpstream
                      : kPacketLifecycleAnchorPublishDownstream;
  if (!packettunnelLifecycleAnchorBind(t)) {
    LOGF("NEPacketDevice: packet publication side is not chained "
         "(direction=%d, next=%p, prev=%p)",
         state->lifecycle_anchor.direction, (void *)t->next, (void *)t->prev);
    startupFailureRecord(1);
    return;
  }
  state->buffer_padding =
      bufferpoolGetLargeBufferPadding(getWorkerBufferPool(0));
  mutexLock(&state->ingress_mutex);
  state->ready = true;
  mutexUnlock(&state->ingress_mutex);
}
