#include "SRPWaterWallBridge.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__,       \
              #condition);                                                     \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

typedef struct poc_state_s {
  atomic_int ready;
  atomic_int failure;
  atomic_int packets;
  atomic_int syn_ack;
  atomic_int http_response;
  uint8_t syn_ack_sequence[4];
  uint16_t destination_port;
} poc_state_t;

typedef struct server_state_s {
  int fd;
  pthread_t thread;
  atomic_int accepted;
  uint16_t port;
} server_state_t;

static void packetCallback(void *context, const uint8_t *packet,
                           size_t length) {
  poc_state_t *state = context;
  atomic_fetch_add(&state->packets, 1);
  if (length >= 40) {
    fprintf(stderr,
            "packet %zu: %u.%u.%u.%u -> %u.%u.%u.%u proto=%u flags=%02x\n",
            length, packet[12], packet[13], packet[14], packet[15], packet[16],
            packet[17], packet[18], packet[19], packet[9], packet[33]);
  }
  if (length >= 40 && packet[0] == 0x45 && packet[9] == IPPROTO_TCP) {
    const uint8_t *tcp = packet + 20;
    uint16_t source;
    uint16_t destination;
    memcpy(&source, tcp, sizeof(source));
    memcpy(&destination, tcp + 2, sizeof(destination));
    if (ntohs(source) == state->destination_port &&
        ntohs(destination) == 12345 &&
        (tcp[13] & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
      memcpy(state->syn_ack_sequence, tcp + 4, sizeof(state->syn_ack_sequence));
      atomic_store(&state->syn_ack, 1);
    }
    const size_t payload_offset = 20 + ((tcp[12] >> 4) * 4);
    if (length >= payload_offset + 5 &&
        memcmp(packet + payload_offset, "HTTP/", 5) == 0) {
      atomic_store(&state->http_response, 1);
    }
  }
}

static void logCallback(void *context, int level, const char *message,
                        size_t length) {
  (void)context;
  (void)level;
  fprintf(stderr, "%.*s\n", (int)length, message);
}

static void readyCallback(void *context) {
  poc_state_t *state = context;
  atomic_store(&state->ready, 1);
}

static void failureCallback(void *context, int code, const char *message) {
  poc_state_t *state = context;
  fprintf(stderr, "runtime failure %d: %s\n", code, message);
  atomic_store(&state->failure, code == 0 ? 1 : code);
}

static uint64_t nowMilliseconds(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return ((uint64_t)now.tv_sec * 1000U) + ((uint64_t)now.tv_nsec / 1000000U);
}

static void waitForImpl(atomic_int *value, const char *name) {
  const uint64_t deadline = nowMilliseconds() + 15000U;
  while (atomic_load(value) == 0 && nowMilliseconds() < deadline) {
    usleep(10000);
  }
  fprintf(stderr, "wait %s = %d\n", name, atomic_load(value));
  CHECK(atomic_load(value) != 0);
}

#define waitFor(value) waitForImpl(value, #value)

static void *acceptOnce(void *context) {
  server_state_t *server = context;
  const int client = accept(server->fd, NULL, NULL);
  CHECK(client >= 0);
  atomic_store(&server->accepted, 1);
  char request[1024];
  const ssize_t received = read(client, request, sizeof(request));
  CHECK(received > 0);
  CHECK(memmem(request, (size_t)received, "GET /", 5) != NULL);
  static const char response[] =
      "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
  CHECK(write(client, response, sizeof(response) - 1) ==
        (ssize_t)(sizeof(response) - 1));
  close(client);
  return NULL;
}

static void startServer(server_state_t *server) {
  struct sockaddr_in address = {.sin_family = AF_INET,
                                .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  socklen_t length = sizeof(address);
  server->fd = socket(AF_INET, SOCK_STREAM, 0);
  CHECK(server->fd >= 0);
  CHECK(bind(server->fd, (struct sockaddr *)&address, sizeof(address)) == 0);
  CHECK(listen(server->fd, 1) == 0);
  CHECK(getsockname(server->fd, (struct sockaddr *)&address, &length) == 0);
  server->port = ntohs(address.sin_port);
  CHECK(pthread_create(&server->thread, NULL, acceptOnce, server) == 0);
}

static uint16_t checksum(const uint8_t *bytes, size_t length) {
  uint32_t sum = 0;
  for (size_t i = 0; i + 1 < length; i += 2) {
    sum += ((uint32_t)bytes[i] << 8) | bytes[i + 1];
  }
  if ((length & 1U) != 0) {
    sum += (uint32_t)bytes[length - 1] << 8;
  }
  while ((sum >> 16) != 0) {
    sum = (sum & 0xffffU) + (sum >> 16);
  }
  return (uint16_t)~sum;
}

static void makeTcp(uint8_t packet[40], uint16_t destination_port,
                    uint8_t flags, uint32_t sequence,
                    uint32_t acknowledgement) {
  memset(packet, 0, 40);
  packet[0] = 0x45;
  packet[2] = 0;
  packet[3] = 40;
  packet[4] = 0x12;
  packet[5] = 0x34;
  packet[8] = 64;
  packet[9] = IPPROTO_TCP;
  packet[12] = 10;
  packet[15] = 2;
  if (getenv("POC_REMOTE_IP") != NULL) {
    CHECK(inet_pton(AF_INET, getenv("POC_REMOTE_IP"), packet + 16) == 1);
  } else {
    packet[16] = 127;
    packet[19] = 1;
  }
  const uint16_t ip_sum = checksum(packet, 20);
  packet[10] = (uint8_t)(ip_sum >> 8);
  packet[11] = (uint8_t)ip_sum;

  uint8_t *tcp = packet + 20;
  tcp[0] = 12345 >> 8;
  tcp[1] = 12345 & 0xff;
  tcp[2] = (uint8_t)(destination_port >> 8);
  tcp[3] = (uint8_t)destination_port;
  tcp[4] = (uint8_t)(sequence >> 24);
  tcp[5] = (uint8_t)(sequence >> 16);
  tcp[6] = (uint8_t)(sequence >> 8);
  tcp[7] = (uint8_t)sequence;
  tcp[8] = (uint8_t)(acknowledgement >> 24);
  tcp[9] = (uint8_t)(acknowledgement >> 16);
  tcp[10] = (uint8_t)(acknowledgement >> 8);
  tcp[11] = (uint8_t)acknowledgement;
  tcp[12] = 5U << 4;
  tcp[13] = flags;
  tcp[14] = 0xff;
  tcp[15] = 0xff;

  uint8_t pseudo[12] = {10, 0, 0, 2, 127, 0, 0, 1, 0, IPPROTO_TCP, 0, 20};
  uint32_t sum = 0;
  for (size_t i = 0; i < sizeof(pseudo); i += 2) {
    sum += ((uint32_t)pseudo[i] << 8) | pseudo[i + 1];
  }
  for (size_t i = 0; i < 20; i += 2) {
    sum += ((uint32_t)tcp[i] << 8) | tcp[i + 1];
  }
  while ((sum >> 16) != 0) {
    sum = (sum & 0xffffU) + (sum >> 16);
  }
  const uint16_t tcp_sum = (uint16_t)~sum;
  tcp[16] = (uint8_t)(tcp_sum >> 8);
  tcp[17] = (uint8_t)tcp_sum;
}

static size_t makeHttpRequest(uint8_t *packet, uint16_t destination_port,
                              uint32_t acknowledgement) {
  static const char request[] =
      "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
  const size_t payload_length = sizeof(request) - 1;
  const size_t packet_length = 40 + payload_length;
  makeTcp(packet, destination_port, TH_ACK | TH_PUSH, 2, acknowledgement);
  memcpy(packet + 40, request, payload_length);
  packet[2] = (uint8_t)(packet_length >> 8);
  packet[3] = (uint8_t)packet_length;
  packet[10] = packet[11] = 0;
  const uint16_t ip_sum = checksum(packet, 20);
  packet[10] = (uint8_t)(ip_sum >> 8);
  packet[11] = (uint8_t)ip_sum;
  packet[36] = packet[37] = 0;
  uint8_t pseudo[12];
  memcpy(pseudo, packet + 12, 8);
  pseudo[8] = 0;
  pseudo[9] = IPPROTO_TCP;
  pseudo[10] = (uint8_t)((packet_length - 20) >> 8);
  pseudo[11] = (uint8_t)(packet_length - 20);
  uint32_t sum = 0;
  for (size_t i = 0; i < sizeof(pseudo); i += 2) {
    sum += ((uint32_t)pseudo[i] << 8) | pseudo[i + 1];
  }
  for (size_t i = 20; i < packet_length; i += 2) {
    sum += ((uint32_t)packet[i] << 8) | packet[i + 1];
  }
  while ((sum >> 16) != 0) {
    sum = (sum & 0xffffU) + (sum >> 16);
  }
  const uint16_t tcp_sum = (uint16_t)~sum;
  packet[36] = (uint8_t)(tcp_sum >> 8);
  packet[37] = (uint8_t)tcp_sum;
  return packet_length;
}

static SRPWaterWallBridge *startRuntime(poc_state_t *state,
                                        const char *nodes_json) {
  SRPWaterWallCallbacks callbacks = {.packet = packetCallback,
                                     .log = logCallback,
                                     .ready = readyCallback,
                                     .failure = failureCallback,
                                     .context = state};
  const char *core_json =
      getenv("POC_DEBUG") != NULL
          ? "{\"log\":{\"core\":{\"loglevel\":\"DEBUG\",\"console\":true},"
            "\"network\":{\"loglevel\":\"DEBUG\",\"console\":true}},"
            "\"misc\":{\"workers\":1,\"ram-profile\":\"minimal\",\"mtu\":1420},"
            "\"configs\":[\"hosted-nodes.json\"]}"
      : getenv("POC_MINIMAL") != NULL
          ? "{\"misc\":{\"workers\":1,\"ram-profile\":\"minimal\",\"mtu\":1420,"
            "\"splice\":false,\"try-enabling-bbr\":false,\"tcp-tune\":false},"
            "\"configs\":[\"hosted-nodes.json\"]}"
          : "{\"configs\":[\"hosted-nodes.json\"]}";
  SRPWaterWallConfig config = {.core_json = core_json,
                               .nodes_json = nodes_json};
  SRPWaterWallBridge *bridge = SRPWaterWallBridgeStart(&config, &callbacks);
  CHECK(bridge != NULL);
  return bridge;
}

int main(void) {
  static const char invalid_nodes[] = "{\"name\":\"bad\",\"nodes\":[]}";
  static const char nodes_template[] =
      "{\"name\":\"poc\",\"nodes\":["
      "{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"settings\":{},\"next\":"
      "\"ptc\"},"
      "{\"name\":\"ptc\",\"type\":\"PacketsToConnection\",\"settings\":{"
      "\"mtu\":1500},\"next\":\"out\"},"
      "{\"name\":\"out\",\"type\":\"TcpUdpConnector\",\"settings\":{"
      "\"address\":\"dest_context->address\",\"port\":\"dest_context->port\","
      "\"nodelay\":true}}]}";
  char nodes[32768];
  const char *config_path = getenv("POC_REMOTE_CONFIG");
  if (config_path != NULL) {
    FILE *config = fopen(config_path, "rb");
    CHECK(config != NULL);
    const size_t length = fread(nodes, 1, sizeof(nodes) - 1, config);
    fclose(config);
    CHECK(length > 0 && length < sizeof(nodes) - 1);
    nodes[length] = '\0';
  } else {
    snprintf(nodes, sizeof(nodes), "%s", nodes_template);
  }

  poc_state_t state = {0};
  SRPWaterWallBridge *bridge = NULL;
  if (getenv("POC_SKIP_INVALID") == NULL) {
    bridge = startRuntime(&state, invalid_nodes);
    waitFor(&state.failure);
    CHECK(SRPWaterWallBridgeStop(bridge) == 0);
  }

  server_state_t server = {0};
  const bool remote = getenv("POC_REMOTE_IP") != NULL;
  if (!remote) {
    startServer(&server);
  }
  state.destination_port =
      remote ? atoi(getenv("POC_REMOTE_PORT")) : server.port;
  atomic_store(&state.failure, 0);
  bridge = startRuntime(&state, nodes);
  waitFor(&state.ready);

  uint8_t packet[512];
  makeTcp(packet, state.destination_port, TH_SYN, 1, 0);
  if (remote) {
    CHECK(inet_pton(AF_INET, getenv("POC_REMOTE_IP"), packet + 16) == 1);
    if (getenv("POC_SOURCE_IP") != NULL) {
      CHECK(inet_pton(AF_INET, getenv("POC_SOURCE_IP"), packet + 12) == 1);
    }
    packet[10] = packet[11] = 0;
    const uint16_t ip_sum = checksum(packet, 20);
    packet[10] = (uint8_t)(ip_sum >> 8);
    packet[11] = (uint8_t)ip_sum;
    packet[36] = packet[37] = 0;
    uint8_t pseudo[12];
    memcpy(pseudo, packet + 12, 8);
    pseudo[8] = 0;
    pseudo[9] = IPPROTO_TCP;
    pseudo[10] = 0;
    pseudo[11] = 20;
    uint32_t sum = 0;
    for (size_t i = 0; i < sizeof(pseudo); i += 2) {
      sum += ((uint32_t)pseudo[i] << 8) | pseudo[i + 1];
    }
    for (size_t i = 20; i < 40; i += 2) {
      sum += ((uint32_t)packet[i] << 8) | packet[i + 1];
    }
    while ((sum >> 16) != 0) {
      sum = (sum & 0xffffU) + (sum >> 16);
    }
    const uint16_t tcp_sum = (uint16_t)~sum;
    packet[36] = (uint8_t)(tcp_sum >> 8);
    packet[37] = (uint8_t)tcp_sum;
  }
  CHECK(SRPWaterWallBridgeSubmitPacket(bridge, packet, 40) == 0);
  CHECK(SRPWaterWallBridgeSubmitPacket(bridge, packet, 1) == -EINVAL);
  waitFor(&state.syn_ack);
  const uint32_t peer_sequence = ((uint32_t)state.syn_ack_sequence[0] << 24) |
                                 ((uint32_t)state.syn_ack_sequence[1] << 16) |
                                 ((uint32_t)state.syn_ack_sequence[2] << 8) |
                                 state.syn_ack_sequence[3];
  makeTcp(packet, state.destination_port, TH_ACK, 2, peer_sequence + 1U);
  CHECK(SRPWaterWallBridgeSubmitPacket(bridge, packet, 40) == 0);
  if (!remote) {
    waitFor(&server.accepted);
  }
  const size_t request_length =
      makeHttpRequest(packet, state.destination_port, peer_sequence + 1U);
  CHECK(SRPWaterWallBridgeSubmitPacket(bridge, packet, request_length) == 0);
  waitFor(&state.http_response);
  CHECK(atomic_load(&state.failure) == 0);
  CHECK(SRPWaterWallBridgeStop(bridge) == 0);
  if (!remote) {
    CHECK(pthread_join(server.thread, NULL) == 0);
    close(server.fd);
  }

  atomic_store(&state.ready, 0);
  bridge = startRuntime(&state, nodes);
  waitFor(&state.ready);
  CHECK(SRPWaterWallBridgeStop(bridge) == 0);
  puts("host PoC passed");
  return 0;
}
