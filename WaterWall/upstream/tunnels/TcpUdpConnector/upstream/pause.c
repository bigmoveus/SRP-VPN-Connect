#include "structure.h"

void tcpudpconnectorTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    tunnel_t *connector = tcpudpconnectorGetSelectedUpStreamTunnel(t, l);
    if (connector != NULL)
    {
        tunnelUpStreamPause(connector, l);
    }
}
