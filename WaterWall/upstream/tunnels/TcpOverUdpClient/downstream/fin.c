#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{

    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->k_handle != NULL);

    // During our close-frame flush, retire state without reflecting Finish to prev.
    const bool forward    = ls->can_downstream && ! ls->close_initiated;
    const bool drain_held = ls->close_drain_held;
    tcpoverudpclientLinestateDestroy(ls);
    if (forward)
    {
        tunnelPrevDownStreamFinish(t, l);
    }
    tcpoverudpclientCompleteCloseDrain(t, l, drain_held);
}
