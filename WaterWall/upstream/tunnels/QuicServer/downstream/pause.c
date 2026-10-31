#include "structure.h"

void quicserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    /* Not gated on quicCanRelay: a carrier drain still honors the application hold. */
    quicHoldApplication(t, l, true);
}
