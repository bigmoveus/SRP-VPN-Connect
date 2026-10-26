#include "NEPacketDevice/structure.h"

#include "loggers/network_logger.h"

static void nepacketdeviceIngressCancelled(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    tunnel_t                *t = arg1;
    discard                  arg2;
    discard                  arg3;
    discard                  reason;
    nepacketdevice_tstate_t *state = tunnelGetState(t);
    mutexLock(&state->ingress_mutex);
    state->ingress_delivery_pending = false;
    sbuf_t *buf;
    while ((buf = nepacketdeviceQueuePop(&state->ingress)) != NULL)
    {
        sbufDestroy(buf);
    }
    mutexUnlock(&state->ingress_mutex);
}

static void nepacketdeviceDeliverIngress(void *worker, void *arg1, void *arg2, void *arg3)
{
    worker_t *destination = worker;
    tunnel_t *t           = arg1;
    discard   arg2;
    discard   arg3;
    assert(destination->wid == 0 && currentThreadOwnsWorker(destination->wid));
    nepacketdevice_tstate_t *state = tunnelGetState(t);
    line_t                  *line  = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), destination->wid);

    for (uint32_t i = 0; i < kNEPacketIngressDrainQuantum; ++i)
    {
        mutexLock(&state->ingress_mutex);
        sbuf_t *buf = state->ingress_open ? nepacketdeviceQueuePop(&state->ingress) : NULL;
        mutexUnlock(&state->ingress_mutex);
        if (buf == NULL)
        {
            break;
        }
        packettunnelLifecycleAnchorPublish(t, line, buf);
    }

    mutexLock(&state->ingress_mutex);
    const bool more = state->ingress.count != 0 && state->ingress_open;
    if (! more)
    {
        state->ingress_delivery_pending = false;
    }
    mutexUnlock(&state->ingress_mutex);
    if (more && sendWorkerMessageForceQueueWithCleanup(
                    destination->wid, nepacketdeviceDeliverIngress, nepacketdeviceIngressCancelled, t, NULL, NULL) !=
                    kWorkerMessageSubmitAccepted)
    {
        LOGW("NEPacketDevice: ingress continuation was cancelled");
    }
}

int srpNEPacketDeviceSubmit(const void *packet, size_t length)
{
    nepacketdevice_tstate_t *state = srpNEPacketDeviceState;
    if (packet == NULL || length < 20 || length > kNEPacketMaximumSize)
    {
        return -EINVAL;
    }

    mutexLock(&state->ingress_mutex);
    if (! state->ingress_open || ! state->ready)
    {
        mutexUnlock(&state->ingress_mutex);
        return -ENOTCONN;
    }
    if (state->ingress_paused || state->ingress.count == kNEPacketQueueCapacity ||
        state->ingress.bytes + length > kNEPacketQueueByteLimit)
    {
        mutexUnlock(&state->ingress_mutex);
        return -EAGAIN;
    }

    sbuf_t *buf = sbufCreateWithPadding((uint32_t) length, state->buffer_padding);
    sbufSetLength(buf, (uint32_t) length);
    sbufWrite(buf, packet, (uint32_t) length);
    const bool pushed = nepacketdeviceQueuePush(&state->ingress, buf);
    assert(pushed);
    discard pushed;
    bool    schedule = false;
    if (! state->ingress_delivery_pending)
    {
        state->ingress_delivery_pending = true;
        schedule                        = true;
    }
    mutexUnlock(&state->ingress_mutex);

    if (schedule && sendWorkerMessageForceQueueWithCleanup(
                        0, nepacketdeviceDeliverIngress, nepacketdeviceIngressCancelled, state->owner, NULL, NULL) !=
                        kWorkerMessageSubmitAccepted)
    {
        return -ENOTCONN;
    }
    return 0;
}
