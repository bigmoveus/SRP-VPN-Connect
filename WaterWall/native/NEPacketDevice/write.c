#include "NEPacketDevice/structure.h"

static void nepacketdeviceDrainEgress(tunnel_t *t, line_t *line) {
  nepacketdevice_tstate_t *state = tunnelGetState(t);
  state->egress_callback_active = true;
  sbuf_t *buf;
  while (state->packet_callback != NULL &&
         (buf = nepacketdeviceQueuePop(&state->egress)) != NULL) {
    SRPNEPacketWriteCallback callback = state->packet_callback;
    callback(state->callback_context, sbufGetRawPtr(buf), sbufGetLength(buf));
    lineReuseBuffer(line, buf);
  }
  state->egress_callback_active = false;
}

void nepacketdeviceTunnelWritePayload(tunnel_t *t, line_t *line, sbuf_t *buf) {
  nepacketdevice_tstate_t *state = tunnelGetState(t);
  assert(lineIsOnCurrentWorker(line) && lineGetWID(line) == 0);
  if (!packettunnelConsumeChecksumRequest(buf) || state->worker_quiesced ||
      state->packet_callback == NULL) {
    lineReuseBuffer(line, buf);
    return;
  }
  if (state->egress_callback_active || state->egress.count != 0) {
    if (!nepacketdeviceQueuePush(&state->egress, buf)) {
      lineReuseBuffer(line, buf);
    }
    return;
  }

  state->egress_callback_active = true;
  SRPNEPacketWriteCallback callback = state->packet_callback;
  callback(state->callback_context, sbufGetRawPtr(buf), sbufGetLength(buf));
  lineReuseBuffer(line, buf);
  state->egress_callback_active = false;
  nepacketdeviceDrainEgress(t, line);
}

void nepacketdeviceTunnelDownstreamPause(tunnel_t *t, line_t *line) {
  discard line;
  nepacketdevice_tstate_t *state = tunnelGetState(t);
  mutexLock(&state->ingress_mutex);
  state->ingress_paused = true;
  mutexUnlock(&state->ingress_mutex);
}

void nepacketdeviceTunnelDownstreamResume(tunnel_t *t, line_t *line) {
  discard line;
  nepacketdevice_tstate_t *state = tunnelGetState(t);
  mutexLock(&state->ingress_mutex);
  state->ingress_paused = false;
  mutexUnlock(&state->ingress_mutex);
}
