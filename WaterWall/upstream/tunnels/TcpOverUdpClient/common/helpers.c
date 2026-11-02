#include "structure.h"

#include "loggers/network_logger.h"

static bool tcpoverudpclientQueuePacketContext(context_queue_t *queue, line_t *l, const uint8_t *packet,
                                               size_t packet_len)
{
    // Only KCP output reaches here, with at most the optional FEC envelope added.
    assert(packet != NULL && packet_len > 0 &&
           packet_len <= kTcpOverUdpClientKcpMaximumMtu + kTcpOverUdpFecOuterHeaderSize);

    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *buf  = NULL;

    if (packet_len <= bufferpoolGetSmallBufferSize(pool))
    {
        buf = bufferpoolGetSmallBuffer(pool);
    }
    else if (packet_len <= bufferpoolGetLargeBufferSize(pool))
    {
        buf = bufferpoolGetLargeBuffer(pool);
    }
    else
    {
        return false;
    }

    sbufSetLength(buf, (uint32_t) packet_len);
    sbufWriteLarge(buf, packet, (uint32_t) packet_len);
    context_t *ctx = contextCreatePayload(l, buf);
    contextqueuePush(queue, ctx);
    return true;
}

static bool tcpoverudpclientEmitOuterPacket(void *ctx, const uint8_t *packet, size_t packet_len)
{
    tcpoverudpclient_lstate_t *ls = (tcpoverudpclient_lstate_t *) ctx;

    assert(ls != NULL && ls->k_handle != NULL && ls->line != NULL && lineIsAlive(ls->line));

    return tcpoverudpclientQueuePacketContext(&ls->cq_u, ls->line, packet, packet_len);
}

bool tcpoverudpclientInputKcpPacket(void *ctx, const uint8_t *packet, size_t packet_len)
{
    tcpoverudpclient_lstate_t *ls = (tcpoverudpclient_lstate_t *) ctx;

    assert(ls != NULL && ls->k_handle != NULL);

    // FEC validated the shard's uint16 length prefix before calling us.
    assert(packet != NULL && packet_len <= UINT16_MAX - 2U);

    return ikcp_input(ls->k_handle, (const char *) packet, (long) packet_len) >= 0;
}

void tcpoverudpclientBeginClose(tcpoverudpclient_lstate_t *ls)
{
    if (ls->close_initiated)
    {
        return;
    }
    ls->close_initiated = true;
    lineBeginCloseDrain(ls->line);
    ls->close_drain_held                = true;
    const tcpoverudpclient_tstate_t *ts = tunnelGetState(ls->tunnel);
    ls->close_deadline                  = wloopNowMS(getWorkerLoop(lineGetWID(ls->line))) + ts->no_recv_timeout_ms;
}

void tcpoverudpclientCompleteCloseDrain(tunnel_t *t, line_t *l, bool drain_held)
{
    if (drain_held && lineEndCloseDrain(l))
    {
        if (lineIsAlive(l))
        {
            tunnelNextUpStreamFinish(t, l);
        }
        if (lineIsAlive(l))
        {
            lineDestroy(l);
        }
    }
}

void tcpoverudpclientReleaseClosing(tunnel_t *t, line_t *l, tcpoverudpclient_lstate_t *ls)
{
    const bool drain_held = ls->close_drain_held;
    tcpoverudpclientLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);
    tcpoverudpclientCompleteCloseDrain(t, l, drain_held);
}

static void tcpoverudpclientSendQueuedPackets(tunnel_t *t, line_t *l, tcpoverudpclient_lstate_t *ls)
{
    while (lineIsAlive(l) && ls->k_handle != NULL && contextqueueLen(&ls->cq_u) > 0)
    {
        context_t *c = contextqueuePop(&ls->cq_u);
        contextApplyOnNextTunnelU(c, t);
        contextDestroy(c);
    }
}

static void tcpoverudpclientFinishCloseIfSettled(tunnel_t *t, line_t *l, tcpoverudpclient_lstate_t *ls,
                                                 uint64_t current_time)
{
    if (! ls->close_initiated || (ikcp_waitsnd(ls->k_handle) > 0 && current_time < ls->close_deadline))
    {
        return;
    }
    if (ikcp_waitsnd(ls->k_handle) > 0)
    {
        LOGW("TcpOverUdpClient: KCP close delivery deadline expired: queued=%d snd_buf=%u snd_queue=%u "
             "snd_una=%u snd_nxt=%u rcv_nxt=%u source_paused=%d downstream_paused=%d can_downstream=%d",
             ikcp_waitsnd(ls->k_handle), ls->k_handle->nsnd_buf, ls->k_handle->nsnd_que,
             ls->k_handle->snd_una, ls->k_handle->snd_nxt, ls->k_handle->rcv_nxt,
             ls->source_paused, ls->downstream_paused, ls->can_downstream);
    }
    // A server releases its line when it reads this frame, without acknowledging it. The frame goes out once and
    // nothing follows it: a retransmission would open a new server line on this UDP port, and a later client line
    // that reuses the port would wait forever for a sequence number that line already sent.
    const uint8_t close_buf[kFrameHeaderLength] = {kFrameFlagClose};
    if (ikcp_send(ls->k_handle, (const char *) close_buf, (int) sizeof(close_buf)) == sizeof(close_buf))
    {
        ikcp_flush(ls->k_handle);
        tcpoverudpclientSendQueuedPackets(t, l, ls);
    }
    else
    {
        LOGW("TcpOverUdpClient: failed to queue the KCP close frame");
    }
    if (lineIsAlive(l) && ls->k_handle != NULL)
    {
        tcpoverudpclientReleaseClosing(t, l, ls);
    }
}

void tcpoverudpclientRecordLinkQuality(tcpoverudpclient_lstate_t *ls, uint64_t now_ms, bool final)
{
    const ikcpcb *kcp = ls->k_handle;
    linkqualityRecordCarrier(&ls->quality, now_ms, final, kcp->sent_segments, kcp->resent_segments,
                             ls->received_bytes, (uint32_t) max(kcp->rx_srtt, 0), (uint32_t) max(kcp->rx_rto, 0));
}

bool tcpoverudpclientUpdateKcp(tcpoverudpclient_lstate_t *ls, bool flush)
{
    assert(ls != NULL && ls->k_handle != NULL && ls->line != NULL && lineIsAlive(ls->line));

    line_t   *l            = ls->line;
    tunnel_t *t            = ls->tunnel;
    uint64_t  current_time = wloopNowMS(getWorkerLoop(lineGetWID(l)));

    lineRef(l);

    if (flush)
    {
        ikcp_flush(ls->k_handle);
    }
    ikcp_update(ls->k_handle, (IUINT32) current_time);
    tcpoverudpclientRecordLinkQuality(ls, current_time, false);

    tcpoverudpclientSendQueuedPackets(t, l, ls);

    // Reconcile our own pressure only after KCP and packet output have settled.
    // ACK-only input can release the hold without producing another packet.
    if (lineIsAlive(l) && ls->k_handle != NULL && ls->can_downstream)
    {
        const int queued = ikcp_waitsnd(ls->k_handle);
        const int limit  = tcpoverudpclientGetKcpSendBufferLimit(ls);
        if (! ls->source_paused && queued > limit)
        {
            ls->source_paused = true;
            tunnelPrevDownStreamPause(t, l);
        }
        else if (ls->source_paused && queued < limit)
        {
            ls->source_paused = false;
            tunnelPrevDownStreamResume(t, l);
        }
    }
    if (lineIsAlive(l) && ls->k_handle != NULL)
    {
        tcpoverudpclientFinishCloseIfSettled(t, l, ls, current_time);
    }
    const bool alive = lineIsAlive(l) && ls->k_handle != NULL;

    lineUnref(l);
    return alive;
}

static uint32_t tcpoverudpclientGetNextKcpDelay(tcpoverudpclient_lstate_t *ls, uint64_t current_time)
{
    IUINT32 current32        = (IUINT32) current_time;
    IUINT32 next_update_time = ikcp_check(ls->k_handle, current32);
    IINT32  delay            = (IINT32) (next_update_time - current32);
    if (delay <= 0)
    {
        return 1U;
    }
    if (ls->close_initiated && ls->close_deadline > current_time)
    {
        return (uint32_t) min((uint64_t) delay, ls->close_deadline - current_time);
    }
    return (uint32_t) delay;
}

void tcpoverudpclientKcpLoopIntervalCallback(wtimer_t *timer)
{

    tcpoverudpclient_lstate_t *ls = weventGetUserdata(timer);

    assert(ls != NULL && ls->k_timer == timer && ls->k_handle != NULL && ls->line != NULL && ls->tunnel != NULL &&
           lineIsAlive(ls->line));

    uint64_t                   current_time = wloopNowMS(getWorkerLoop(lineGetWID(ls->line)));
    tcpoverudpclient_tstate_t *ts           = tunnelGetState(ls->tunnel);
    const uint64_t             idle_ms      = wloopNowMonotonicMS(getWorkerLoop(lineGetWID(ls->line))) - ls->last_recv;

    if (! ls->close_initiated && idle_ms > ts->ping_interval_ms)
    {
        if (! ls->ping_sent)
        {
            ls->ping_sent                        = true;
            uint8_t ping_buf[kFrameHeaderLength] = {kFrameFlagPing};
            ikcp_send(ls->k_handle, (const char *) ping_buf, (int) sizeof(ping_buf));
        }
        else if (idle_ms > ts->no_recv_timeout_ms)
        {
            LOGW("TcpOverUdpClient -> KCP[%d]: no data received for too long, closing connection", ls->k_handle->conv);

            tunnel_t *t           = ls->tunnel;
            line_t   *l           = ls->line;
            ls->receive_timed_out = true;
            tcpoverudpclientBeginClose(ls);
            ls->close_deadline = current_time;

            lineRef(l);
            tunnelPrevDownStreamFinish(t, l);
            if (lineIsAlive(l))
            {
                discard tcpoverudpclientUpdateKcp(ls, true);
            }
            lineUnref(l);
            return;
        }
    }

    if (tcpoverudpclientUpdateKcp(ls, false))
    {
        wtimerReset(timer, tcpoverudpclientGetNextKcpDelay(ls, current_time));
    }
}

int tcpoverudpclientKUdpOutput(const char *data, int len, ikcpcb *kcp, void *user)
{
    discard kcp;

    tcpoverudpclient_lstate_t *ls = (tcpoverudpclient_lstate_t *) user;

    assert(ls != NULL && ls->k_handle != NULL && ls->line != NULL && lineIsAlive(ls->line));
    line_t *l = ls->line;

    if (ls->fec_encoder != NULL)
    {
        if (! tcpoverudpFecEncodePacket(
                ls->fec_encoder, (const uint8_t *) data, (size_t) len, tcpoverudpclientEmitOuterPacket, ls))
        {
            return -1;
        }
        return 0;
    }

    return tcpoverudpclientQueuePacketContext(&ls->cq_u, l, (const uint8_t *) data, (size_t) len) ? 0 : -1;
}
