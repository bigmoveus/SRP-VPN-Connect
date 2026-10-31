#include "structure.h"

void quicserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    if (quicCanRelay(t, l))
    {
        quicSetCarrierPaused(t, l, true);
    }
}
