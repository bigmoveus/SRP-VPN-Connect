#include "structure.h"

void packetsplitstreamTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    packetsplitstream_tstate_t *ts = tunnelGetState(t);

    tunnelUpStreamPayload(ts->up_tunnel, l, buf);
}
