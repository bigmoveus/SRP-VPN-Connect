#include "structure.h"

#include "loggers/network_logger.h"

static void udpconnectorPoolSocketReconcileRead(udpconnector_pool_socket_t *sock)
{
    if (sock->state == kUdpConnectorPoolSocketClosing || sock->active_bindings_count == 0)
    {
        return;
    }
    if (sock->read_paused_count == sock->active_bindings_count)
    {
        if (! sock->read_stopped && sock->io != NULL)
        {
            wioReadStop(sock->io);
            sock->read_stopped = true;
        }
        return;
    }
    if (sock->read_stopped && sock->io != NULL)
    {
        if (wioRead(sock->io) == 0)
        {
            sock->read_stopped = false;
        }
    }
}

void udpconnectorSetReadPaused(udpconnector_lstate_t *ls, bool paused)
{
    if (ls->read_paused == paused)
    {
        return;
    }
    ls->read_paused = paused;
    for (udpconnector_binding_t *binding = ls->bindings_head; binding != NULL; binding = binding->line_next)
    {
        assert(binding->active && binding->socket_linked);
        udpconnector_pool_socket_t *sock = binding->socket;
        if (paused)
        {
            ++sock->read_paused_count;
        }
        else
        {
            assert(sock->read_paused_count > 0);
            --sock->read_paused_count;
        }
        udpconnectorPoolSocketReconcileRead(sock);
    }
}

void udpconnectorSocketBindingAttached(udpconnector_pool_socket_t *sock, const udpconnector_lstate_t *ls)
{
    if (ls->read_paused)
    {
        ++sock->read_paused_count;
    }
    udpconnectorPoolSocketReconcileRead(sock);
}

void udpconnectorSocketBindingDetached(udpconnector_pool_socket_t *sock, const udpconnector_lstate_t *ls)
{
    if (ls->read_paused)
    {
        assert(sock->read_paused_count > 0);
        --sock->read_paused_count;
    }
    udpconnectorPoolSocketReconcileRead(sock);
}

void udpconnectorTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    udpconnector_lstate_t *ls = lineGetState(l, t);

    udpconnectorSetReadPaused(ls, true);
}
