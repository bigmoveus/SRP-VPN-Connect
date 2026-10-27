#include "structure.h"

#include "../../Internals/Bgp4Common/stream.h"
#include "loggers/network_logger.h"

void tcpoverudpserverDeliverReceived(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);

    lineRef(l);
    while (ls->k_handle != NULL && ! ls->downstream_paused && ! ls->close_initiated)
    {
        buffer_pool_t *pool = lineGetBufferPool(l);
        const int pending = ikcp_peeksize(ls->k_handle);
        if (pending > kBgpMaxWireFrame + kFrameHeaderLength)
        {
            LOGW("TcpOverUdpServer: rejecting oversized KCP message (%d bytes)", pending);
            tcpoverudpserverBeginClose(ls);
            break;
        }
        sbuf_t *large_buf = pending > (int) bufferpoolGetLargeBufferSize(pool)
            ? sbufCreateWithPadding((uint32_t) pending, bufferpoolGetLargeBufferPadding(pool))
            : bufferpoolGetLargeBuffer(pool);
        int read = ikcp_recv(ls->k_handle, (void *) sbufGetMutablePtr(large_buf),
                             (int) sbufGetMaximumWriteableSize(large_buf));

        if (read <= 0)
        {
            if (read == -3) LOGW("TcpOverUdpServer: KCP message exceeds the receive buffer");
            lineReuseBuffer(l, large_buf);
            break;
        }

        sbufSetLength(large_buf, (uint32_t) read);
        uint8_t frame_flag = sbufReadUI8(large_buf);
        sbufShiftRight(large_buf, kFrameHeaderLength);

        if (! ls->can_upstream)
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
            tunnelNextUpStreamPayload(t, l, large_buf);
        }
        else if (frame_flag == kFrameFlagClose)
        {
            lineReuseBuffer(l, large_buf);
            if (! ls->close_notified)
            {
                ls->close_notified = true;
                ls->can_upstream   = false;
                tcpoverudpserverBeginClose(ls);
                if (tcpoverudpserverUpdateKcp(ls, true) && lineIsAlive(l))
                {
                    tunnelNextUpStreamFinish(t, l);
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
            LOGE("TcpOverUdpServer: Unknown frame flag: %02X", frame_flag);
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
        discard tcpoverudpserverUpdateKcp(ls, true);
    }
    lineUnref(l);
}

void tcpoverudpserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);

    assert(ls->k_handle != NULL);

    ls->last_recv = wloopNowMS(getWorkerLoop(lineGetWID(l)));
    ls->ping_sent = false;

    if (ls->fec_decoder != NULL)
    {
        if (! tcpoverudpFecDecodePacket(ls->fec_decoder,
                                        (const uint8_t *) sbufGetRawPtr(buf),
                                        sbufGetLength(buf),
                                        tcpoverudpserverInputKcpPacket,
                                        ls))
        {
            LOGW("TcpOverUdpServer: dropped invalid FEC packet");
        }
    }
    else
    {
        ikcp_input(ls->k_handle, (const char *) sbufGetRawPtr(buf), (long) sbufGetLength(buf));
    }
    lineReuseBuffer(l, buf);

    if (tcpoverudpserverUpdateKcp(ls, false) && ! ls->downstream_paused && ! ls->close_initiated)
    {
        tcpoverudpserverDeliverReceived(t, l);
    }
}
