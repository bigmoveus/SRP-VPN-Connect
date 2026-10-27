#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);

    assert(ls->k_handle != NULL);

    lineRef(l);

    tcpoverudpserver_tstate_t *state = tunnelGetState(t);
    if (UNLIKELY(atomicLoadRelaxed(&state->stopping)))
    {
        const bool drain_held = ls->close_drain_held;
        tcpoverudpserverLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        tcpoverudpserverCompleteCloseDrain(t, l, drain_held);
        lineUnref(l);
        return;
    }

    tcpoverudpserverBeginClose(ls);
    discard tcpoverudpserverUpdateKcp(ls, true);

    lineUnref(l);
}
