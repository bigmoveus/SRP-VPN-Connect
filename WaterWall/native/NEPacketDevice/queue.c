#include "NEPacketDevice/structure.h"

static uint32_t nepacketdeviceQueueTail(const nepacketdevice_queue_t *queue)
{
    return (queue->head + queue->count) % kNEPacketQueueCapacity;
}

bool nepacketdeviceQueuePush(nepacketdevice_queue_t *queue, sbuf_t *buf)
{
    const uint32_t length = sbufGetLength(buf);
    if (queue->count == kNEPacketQueueCapacity || queue->bytes + length > kNEPacketQueueByteLimit)
    {
        return false;
    }
    queue->entries[nepacketdeviceQueueTail(queue)] = buf;
    queue->count++;
    queue->bytes += length;
    return true;
}

sbuf_t *nepacketdeviceQueuePop(nepacketdevice_queue_t *queue)
{
    if (queue->count == 0)
    {
        return NULL;
    }
    sbuf_t *buf                 = queue->entries[queue->head];
    queue->entries[queue->head] = NULL;
    queue->bytes -= sbufGetLength(buf);
    queue->head = (queue->head + 1) % kNEPacketQueueCapacity;
    queue->count--;
    return buf;
}
