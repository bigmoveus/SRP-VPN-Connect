#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    udpconnector_lstate_t *ls = lineGetState(l, t);
    if (l->close_drain_count > 0)
    {
        l->close_deferred = true;
        return;
    }
    udpconnectorLineDetach(t, l, ls, kUdpConnectorDetachFinish);
}
