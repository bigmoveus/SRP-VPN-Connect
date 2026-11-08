#include "structure.h"

static void clientHoldDelivery(tunnel_t *t, line_t *l, bool held)
{
    kcpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->role == kKcpClientApplication && ls->session != NULL);
    // Pausing the datagram carrier instead would drop packets and their acknowledgements.
    if (ls->session->driver != NULL)
        touSessionHoldDelivery(ls->session->driver, held);
}

void kcpclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    clientHoldDelivery(t, l, true);
}

void kcpclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    clientHoldDelivery(t, l, false);
}
