#include "structure.h"

#include "loggers/network_logger.h"

bool ptcEnsureNextInit(tunnel_t *t, line_t *l, ptc_lstate_t *ls)
{
    if (ls->next_init_sent)
    {
        return true;
    }

    ls->next_init_sent = true;
    return lineCallWithRef(l, tunnelNextUpStreamInit, t);
}

void ptcOpenLineTask(tunnel_t *t, line_t *l)
{
    if (! ptcNextGateEnter(t))
    {
        ptcCloseLineForStop(t, l);
        return;
    }

    ptc_lstate_t *ls = lineGetState(l, t);

    if (! ptcEnsureNextInit(t, l, ls))
    {
        ptcNextGateLeave(t);
        return;
    }

    ls = lineGetState(l, t);
    if (ls->kind == kPtcLineKindUdp && ! ptcArmUdpIdleOnOwnerThread(ls))
    {
        ptcCloseLineFromNetwork(t, l);
    }
    ptcNextGateLeave(t);
}

static bool ptcQueueUdpStartup(ptc_lstate_t *ls, sbuf_t *buf)
{
    enum
    {
        kUdpStartupMaxBytes     = 64U * 1024U,
        kUdpStartupMaxDatagrams = 64U
    };
    if (ls->udp_delivery_started)
    {
        return false;
    }
    const uint32_t length = sbufGetLength(buf);
    if (length > kUdpStartupMaxBytes || ls->udp_pending_bytes > kUdpStartupMaxBytes - length ||
        bufferqueueGetBufCount(&ls->udp_pending) >= kUdpStartupMaxDatagrams ||
        ! bufferqueueTryPushBack(&ls->udp_pending, &buf))
    {
        LOGD("PacketsToConnection: UDP startup queue is full; dropping a datagram");
        return false;
    }
    ls->udp_pending_bytes += length;
    return true;
}

void ptcFlushInitialUdp(tunnel_t *t, line_t *l)
{
    if (! lineIsAlive(l))
    {
        return;
    }
    lineRef(l);
    ptc_lstate_t *ls = lineGetState(l, t);
    while (ls->udp_pending_bytes > 0 && ! ls->read_paused)
    {
        sbuf_t *buf = bufferqueuePopFront(&ls->udp_pending);
        if (buf == NULL)
        {
            ls->udp_pending_bytes = 0;
            break;
        }
        ls->udp_pending_bytes -= sbufGetLength(buf);
        const line_task_submit_result_e result = lineScheduleTaskWithBuf(l, ptcDeliverPayloadTask, t, buf, NULL);
        if (result != kLineTaskSubmitAcceptedAsync)
        {
            LOGD("PacketsToConnection: queued UDP startup delivery was rejected (%d)", (int) result);
        }
        if (! lineIsAlive(l))
        {
            break;
        }
        ls = lineGetState(l, t);
    }
    lineUnref(l);
}

void ptcDeliverPayloadTask(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    buffer_pool_t *pool = lineGetBufferPool(l);

    if (! ptcNextGateEnter(t))
    {
        bufferpoolReuseBuffer(pool, buf);
        ptcCloseLineForStop(t, l);
        return;
    }

    ptc_lstate_t *ls       = lineGetState(l, t);
    uint32_t      tcp_read = sbufGetLength(buf);

    if (! ptcEnsureNextInit(t, l, ls))
    {
        bufferpoolReuseBuffer(pool, buf);
        ptcNextGateLeave(t);
        return;
    }

    ls = lineGetState(l, t);

    if (ls->kind == kPtcLineKindUdp)
    {
        LOGD("PacketsToConnection: UDP delivery length=%u paused=%u",
             (unsigned int) tcp_read,
             ls->read_paused ? 1U : 0U);
        if (! ptcArmUdpIdleOnOwnerThread(ls))
        {
            bufferpoolReuseBuffer(pool, buf);
            ptcCloseLineFromNetwork(t, l);
            ptcNextGateLeave(t);
            return;
        }
        if (ls->read_paused)
        {
            if (! ptcQueueUdpStartup(ls, buf))
            {
                lineReuseBuffer(l, buf);
            }
            ptcNextGateLeave(t);
            return;
        }
        ls->udp_delivery_started = true;
    }

    if (! lineCallWithRefWithBuf(l, tunnelNextUpStreamPayload, t, buf))
    {
        ptcNextGateLeave(t);
        return;
    }

    ls = lineGetState(l, t);

    if (ls->kind == kPtcLineKindTcp)
    {
        if (ls->read_paused)
        {
            ww_lwip_engine_t *previous;
            const bool        entered = wwLwipEngineEnter(ls->engine, &previous);
            assert(entered);
            discard    entered;
            const bool accumulated = ptcPausedReadAccumulateLocked(ls, tcp_read);
            wwLwipEngineLeave(ls->engine, previous);
            ptcNextGateLeave(t);
            discard accumulated;
            return;
        }

        ww_lwip_engine_t *previous;
        const bool        entered = wwLwipEngineEnter(ls->engine, &previous);
        assert(entered);
        discard entered;
        discard ptcReturnReceiveCreditLocked(ls, tcp_read);
        wwLwipEngineLeave(ls->engine, previous);
    }
    ptcNextGateLeave(t);
}

void ptcCloseLineTask(tunnel_t *t, line_t *l)
{
    if (! ptcNextGateEnter(t))
    {
        ptcCloseLineForStop(t, l);
        return;
    }
    ptcCloseLineFromNetwork(t, l);
    ptcNextGateLeave(t);
}

void ptcResumeUpstreamTask(tunnel_t *t, line_t *l)
{
    if (! ptcNextGateEnter(t))
    {
        ptcCloseLineForStop(t, l);
        return;
    }
    const ptc_lstate_t *ls = lineGetState(l, t);
    if (! ls->write_paused)
        discard lineCallWithRef(l, tunnelNextUpStreamResume, t);
    ptcNextGateLeave(t);
}
