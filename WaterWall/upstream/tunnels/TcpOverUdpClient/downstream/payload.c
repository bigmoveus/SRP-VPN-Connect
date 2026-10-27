#include "structure.h"

#include "../../Internals/Bgp4Common/stream.h"
#include "loggers/network_logger.h"

void tcpoverudpclientDeliverReceived(tunnel_t *t, line_t *l)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);

    lineRef(l);
    while (ls->k_handle != NULL && ! ls->downstream_paused && ! ls->close_initiated)
    {
        buffer_pool_t *pool = lineGetBufferPool(l);
        const int pending = ikcp_peeksize(ls->k_handle);
        if (pending > kBgpMaxWireFrame + kFrameHeaderLength)
        {
            LOGW("TcpOverUdpClient: rejecting oversized KCP message (%d bytes)", pending);
            tcpoverudpclientBeginClose(ls);
            break;
        }
        sbuf_t *large_buf = pending > (int) bufferpoolGetLargeBufferSize(pool)
            ? sbufCreateWithPadding((uint32_t) pending, bufferpoolGetLargeBufferPadding(pool))
            : bufferpoolGetLargeBuffer(pool);
        int read = ikcp_recv(ls->k_handle, (void *) sbufGetMutablePtr(large_buf),
                             (int) sbufGetMaximumWriteableSize(large_buf));

        if (read <= 0)
        {
            if (read == -3) LOGW("TcpOverUdpClient: KCP message exceeds the receive buffer");
            lineReuseBuffer(l, large_buf);
            break;
        }

        sbufSetLength(large_buf, (uint32_t) read);
        uint8_t frame_flag = sbufReadUI8(large_buf);
        sbufShiftRight(large_buf, kFrameHeaderLength);

        if (! ls->can_downstream)
        {
            lineReuseBuffer(l, large_buf);
            break;
        }

        if (frame_flag == kFrameFlagData)
        {
            if (UNLIKELY(sbufGetLength(large_buf) == 0))
            {
                lineReuseBuffer(l, large_buf);
                continue;
            }
            tunnelPrevDownStreamPayload(t, l, large_buf);
        }
        else if (frame_flag == kFrameFlagClose)
        {
            lineReuseBuffer(l, large_buf);
            if (! ls->close_notified)
            {
                ls->close_notified = true;
                ls->can_downstream = false;
                tcpoverudpclientBeginClose(ls);
                if (tcpoverudpclientUpdateKcp(ls, true) && lineIsAlive(l))
                {
                    tunnelPrevDownStreamFinish(t, l);
                }
            }
            break;
        }
        else if (frame_flag == kFrameFlagPing)
        {
            lineReuseBuffer(l, large_buf);
        }
        else
        {
            LOGE("TcpOverUdpClient: Unknown frame flag: %02X", frame_flag);
            lineReuseBuffer(l, large_buf);
            break;
        }

        if (! lineIsAlive(l) || ls->k_handle == NULL)
        {
            break;
        }
    }
    if (lineIsAlive(l) && ls->k_handle != NULL)
    {
        discard tcpoverudpclientUpdateKcp(ls, true);
    }
    lineUnref(l);
}

void tcpoverudpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);

    assert(ls->k_handle != NULL);

    ls->last_recv = wloopNowMS(getWorkerLoop(lineGetWID(l)));
    ls->ping_sent = false;

    if (ls->fec_decoder != NULL)
    {
        if (! tcpoverudpFecDecodePacket(ls->fec_decoder,
                                        (const uint8_t *) sbufGetRawPtr(buf),
                                        sbufGetLength(buf),
                                        tcpoverudpclientInputKcpPacket,
                                        ls))
        {
            LOGW("TcpOverUdpClient: dropped invalid FEC packet");
        }
    }
    else
    {
        ikcp_input(ls->k_handle, (const char *) sbufGetRawPtr(buf), (long) sbufGetLength(buf));
    }
    lineReuseBuffer(l, buf);

    if (tcpoverudpclientUpdateKcp(ls, false) && ! ls->downstream_paused && ! ls->close_initiated)
    {
        tcpoverudpclientDeliverReceived(t, l);
    }
}
