#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(! ls->can_downstream || ls->k_handle == NULL))
    {
        return;
    }

    // Hold delivery instead of pausing the datagram carrier: KCP keeps reading, acknowledging
    // and advertising its shrinking receive window, so the peer slows down without packet loss.
    ls->downstream_paused = true;
}
