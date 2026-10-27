#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->k_handle != NULL);

    const bool forward    = ls->can_upstream && ! ls->close_initiated;
    const bool drain_held = ls->close_drain_held;
    tcpoverudpserverLinestateDestroy(ls);
    if (forward)
    {
        tunnelNextUpStreamFinish(t, l);
    }
    tcpoverudpserverCompleteCloseDrain(t, l, drain_held);
}
