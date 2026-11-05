#include "structure.h"

void quicclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    quicHoldApplication(t, l, true);
}
