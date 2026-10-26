#pragma once

#include "NEPacketDevice/interface.h"
#include "SRPNEPacketDevice.h"

enum
{
    kNEPacketQueueCapacity       = 64,
    kNEPacketQueueByteLimit      = 1024 * 1024,
    kNEPacketMaximumSize         = 65535,
    kNEPacketIngressDrainQuantum = 16
};

typedef struct nepacketdevice_queue_s
{
    sbuf_t  *entries[kNEPacketQueueCapacity];
    size_t   bytes;
    uint32_t head;
    uint32_t count;
} nepacketdevice_queue_t;

bool    nepacketdeviceQueuePush(nepacketdevice_queue_t *queue, sbuf_t *buf);
sbuf_t *nepacketdeviceQueuePop(nepacketdevice_queue_t *queue);

typedef struct nepacketdevice_tstate_s
{
    packet_lifecycle_anchor_t lifecycle_anchor;
    tunnel_t                 *owner;
    SRPNEPacketWriteCallback  packet_callback;
    SRPNEPacketLogCallback    log_callback;
    void                     *callback_context;
    nepacketdevice_queue_t    ingress;
    nepacketdevice_queue_t    egress;
    uint16_t                  buffer_padding;
    wmutex_t                  ingress_mutex;
    bool                      mutex_initialized;
    bool                      ingress_open;
    bool                      ready;
    bool                      ingress_paused;
    bool                      ingress_delivery_pending;
    bool                      worker_quiesced;
    bool                      egress_callback_active;
} nepacketdevice_tstate_t;

_Static_assert(offsetof(nepacketdevice_tstate_t, lifecycle_anchor) == 0,
               "NEPacketDevice lifecycle anchor must remain the tunnel-state prefix");

extern nepacketdevice_tstate_t *srpNEPacketDeviceState;
