#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(! ls->can_upstream))
    {
        return;
    }

    ls->downstream_paused = false;
    tunnelPrevDownStreamResume(t, l);
    if (lineIsAlive(l) && ls->k_handle != NULL && ! ls->close_initiated)
    {
        tcpoverudpserverDeliverReceived(t, l);
    }
}
