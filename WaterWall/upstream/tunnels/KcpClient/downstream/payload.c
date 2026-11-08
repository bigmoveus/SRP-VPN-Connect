#include "structure.h"

void kcpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    kcpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->role == kKcpClientTransport && ls->session != NULL);
    if (ls->session->driver == NULL)
    {
        lineReuseBuffer(l, buf);
        return;
    }
    ls->session->received_bytes += sbufGetLength(buf);
    touSessionInput(ls->session->driver, buf);
}
