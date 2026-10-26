#include "NEPacketDevice/structure.h"

static void nepacketdeviceDiscardQueue(nepacketdevice_queue_t *queue, line_t *line)
{
    sbuf_t *buf;
    while ((buf = nepacketdeviceQueuePop(queue)) != NULL)
    {
        lineReuseBuffer(line, buf);
    }
}

void nepacketdeviceTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                  context;
    nepacketdevice_tstate_t *state = tunnelGetState(t);
    mutexLock(&state->ingress_mutex);
    state->ingress_open = false;
    mutexUnlock(&state->ingress_mutex);
}

void nepacketdeviceTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard                  context;
    nepacketdevice_tstate_t *state = tunnelGetState(t);
    assert(currentThreadOwnsWorker(wid));
    line_t *line           = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), wid);
    state->worker_quiesced = true;
    mutexLock(&state->ingress_mutex);
    nepacketdeviceDiscardQueue(&state->ingress, line);
    state->ingress_delivery_pending = false;
    mutexUnlock(&state->ingress_mutex);
    nepacketdeviceDiscardQueue(&state->egress, line);
}

void nepacketdeviceTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                  context;
    nepacketdevice_tstate_t *state = tunnelGetState(t);
    state->packet_callback         = NULL;
    state->log_callback            = NULL;
    state->callback_context        = NULL;
}
