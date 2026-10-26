#include "NEPacketDevice/interface.h"

node_t nodeNEPacketDeviceGet(void) {
  const char *type_name = "NEPacketDevice";
  node_t node = {
      .type = stringDuplicate(type_name),
      .hash_type = calcHashBytes(type_name, stringLength(type_name)),
      .version = 0001,
      .createHandle = nepacketdeviceTunnelCreate,
      .flags = kNodeFlagChainHead | kNodeFlagChainEnd,
      .required_padding_left = 0,
      .layer_group = kNodeLayer3,
      .layer_group_next_node = kNodeLayer3,
      .layer_group_prev_node = kNodeLayer3,
      .can_have_next = true,
      .can_have_prev = true,
  };
  return node;
}
