#include "structure.h"

void packetsplitstreamTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    packetsplitstream_tstate_t *ts = tunnelGetState(t);
    tunnelUpStreamInit(ts->up_tunnel, l);
    tunnelUpStreamInit(ts->down_tunnel, l);
}
