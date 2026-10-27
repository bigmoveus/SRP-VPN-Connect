#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);

    assert(ls->k_handle != NULL);

    lineRef(l);

    tcpoverudpclient_tstate_t *state = tunnelGetState(t);
    if (UNLIKELY(atomicLoadRelaxed(&state->stopping)))
    {
        const bool drain_held = ls->close_drain_held;
        tcpoverudpclientLinestateDestroy(ls);
        tunnelNextUpStreamFinish(t, l);
        tcpoverudpclientCompleteCloseDrain(t, l, drain_held);
        lineUnref(l);
        return;
    }

    tcpoverudpclientBeginClose(ls);
    discard tcpoverudpclientUpdateKcp(ls, true);

    lineUnref(l);
}
