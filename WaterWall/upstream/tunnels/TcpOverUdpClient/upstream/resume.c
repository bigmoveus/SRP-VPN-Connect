#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(! ls->can_downstream || ls->k_handle == NULL))
    {
        return;
    }
    ls->downstream_paused = false;
    if (! ls->close_initiated)
    {
        tcpoverudpclientDeliverReceived(t, l);
    }
}
