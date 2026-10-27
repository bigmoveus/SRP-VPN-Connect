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
  atomic_uint_fast64_t next_ack;
  atomic_uint_fast64_t received_payload;
  uint8_t syn_ack_sequence[4];
  uint8_t http_header[5];
  uint8_t http_header_size;
  uint16_t destination_port;
} poc_state_t;

typedef struct server_state_s {
  int fd;
  pthread_t thread;
  atomic_int accepted;
  atomic_uint_fast64_t response_size;
  uint16_t port;
} server_state_t;

static void packetCallback(void *context, const uint8_t *packet,
                           size_t length) {
  poc_state_t *state = context;
  atomic_fetch_add(&state->packets, 1);
  if (getenv("POC_DEBUG") != NULL && length >= 40) {
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
    if (length >= payload_offset && source == htons(state->destination_port) &&
        destination == htons(12345)) {
      const size_t payload_length = length - payload_offset;
      if (payload_length > 0) {
        uint32_t sequence;
        memcpy(&sequence, tcp + 4, sizeof(sequence));
        const uint32_t next = ntohl(sequence) + (uint32_t)payload_length +
                              ((tcp[13] & TH_FIN) != 0 ? 1U : 0U);
        uint_fast64_t previous = atomic_load(&state->next_ack);
        while (previous < next && !atomic_compare_exchange_weak(
                                      &state->next_ack, &previous, next)) {
        }
        atomic_fetch_add(&state->received_payload, payload_length);
        for (size_t i = 0; i < payload_length && state->http_header_size < 5;
             ++i) {
          state->http_header[state->http_header_size++] =
              packet[payload_offset + i];
        }
        if (state->http_header_size == 5 &&
            memcmp(state->http_header, "HTTP/", 5) == 0) {
          atomic_store(&state->http_response, 1);
        }
      }
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

static void writeAll(int fd, const uint8_t *bytes, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    const ssize_t written =
        send(fd, bytes + offset, length - offset, MSG_NOSIGNAL);
    if (written < 0 && errno == EINTR) {
      continue;
    }
    CHECK(written > 0);
    offset += (size_t)written;
  }
}

static void *acceptOnce(void *context) {
  server_state_t *server = context;
  const int client = accept(server->fd, NULL, NULL);
  CHECK(client >= 0);
  atomic_store(&server->accepted, 1);
  char request[1024];
  size_t received = 0;
  while (memmem(request, received, "GET /", 5) == NULL) {
    CHECK(received < sizeof(request));
    const ssize_t count =
        read(client, request + received, sizeof(request) - received);
    CHECK(count > 0);
    received += (size_t)count;
  }
  const char *stress = getenv("POC_STRESS_BYTES");
  const uint64_t body_size = stress != NULL ? strtoull(stress, NULL, 10) : 0;
  CHECK(body_size <= 128U * 1024U * 1024U);
  char response[160];
  const int header_length = snprintf(
      response, sizeof(response),
      "HTTP/1.1 200 OK\r\nContent-Length: %llu\r\nConnection: close\r\n\r\n",
      (unsigned long long)body_size);
  CHECK(header_length > 0 && (size_t)header_length < sizeof(response));
  atomic_store(&server->response_size, (uint64_t)header_length + body_size);
  writeAll(client, (const uint8_t *)response, (size_t)header_length);
  uint8_t body[16384] = {0};
  for (uint64_t offset = 0; offset < body_size; offset += sizeof(body)) {
    writeAll(client, body,
             (size_t)(body_size - offset < sizeof(body) ? body_size - offset
                                                        : sizeof(body)));
  }
  close(client);
  return NULL;
}

static void startServer(server_state_t *server) {
  struct sockaddr_in address = {.sin_family = AF_INET,
                                .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  if (getenv("POC_HTTP_IP") != NULL) {
    CHECK(inet_pton(AF_INET, getenv("POC_HTTP_IP"), &address.sin_addr) == 1);
  }
  if (getenv("POC_HTTP_PORT") != NULL) {
    const long port = strtol(getenv("POC_HTTP_PORT"), NULL, 10);
    CHECK(port > 0 && port <= 65535);
    address.sin_port = htons((uint16_t)port);
  }
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
  static const char nodes_bgp4_template[] =
      "{\"name\":\"poc\",\"nodes\":["
      "{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"settings\":{},\"next\":"
      "\"ptc\"},"
      "{\"name\":\"ptc\",\"type\":\"PacketsToConnection\",\"settings\":{"
      "\"mtu\":1500,\"fake-dns\":{\"enabled\":true,\"address\":\"198.18.0.2\","
      "\"port\":53,\"network\":\"100.64.0.0\",\"netmask\":\"255.192.0.0\","
      "\"cache-size\":10000,\"ttl\":1}},\"next\":\"router\"},"
      "{\"name\":\"router\",\"type\":\"Router\",\"settings\":{"
      "\"resolve-domains\":false},\"next\":\"vless\"},"
      "{\"name\":\"vless\",\"type\":\"VlessClient\",\"settings\":{\"uuid\":"
      "\"00112233-4455-6677-8899-aabbccddeeff\",\"address\":"
      "\"dest_context->address\",\"port\":\"dest_context->port\","
      "\"protocol\":\"dest_context->protocol\",\"domain-strategy\":"
      "\"do-not-resolve-domains\"},\"next\":\"bgp4\"},"
      "{\"name\":\"bgp4\",\"type\":\"Bgp4Client\",\"settings\":{},\"next\":"
      "\"%s\"},%s"
      "{\"name\":\"out\",\"type\":\"%s\",\"settings\":{\"address\":"
      "\"127.0.0.1\",\"port\":%u,\"nodelay\":true}}]}";
  char nodes[32768];
  const char *config_path = getenv("POC_REMOTE_CONFIG");
  if (config_path != NULL) {
    FILE *config = fopen(config_path, "rb");
    CHECK(config != NULL);
    const size_t length = fread(nodes, 1, sizeof(nodes) - 1, config);
    fclose(config);
    CHECK(length > 0 && length < sizeof(nodes) - 1);
    nodes[length] = '\0';
  } else if (getenv("POC_BGP4") != NULL) {
    const bool kcp = getenv("POC_BGP4_KCP") != NULL;
    const char *peer = getenv("POC_BGP4_PORT");
    CHECK(peer != NULL);
    const long port = strtol(peer, NULL, 10);
    CHECK(port > 0 && port <= 65535);
    char kcp_node[2048] = {0};
    if (kcp) {
      const char *settings = getenv("POC_KCP_SETTINGS");
      snprintf(
          kcp_node, sizeof(kcp_node),
          "{\"name\":\"kcp\",\"type\":\"TcpOverUdpClient\",\"settings\":%s,"
          "\"next\":\"out\"},",
          settings != NULL
              ? settings
              : "{\"kcp-recv-window\":512,\"kcp-send-buffer-limit\":512}");
    }
    snprintf(nodes, sizeof(nodes), nodes_bgp4_template, kcp ? "kcp" : "out",
             kcp_node, kcp ? "UdpConnector" : "TcpConnector", (unsigned)port);
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
  if (!remote || getenv("POC_RAW_TRANSPORT") != NULL) {
    startServer(&server);
  }
  const char *remote_port = getenv("POC_REMOTE_PORT");
  CHECK(!remote || remote_port != NULL);
  state.destination_port = remote ? atoi(remote_port) : server.port;
  CHECK(state.destination_port > 0);
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
  atomic_store(&state.next_ack, peer_sequence + 1U);
  CHECK(SRPWaterWallBridgeSubmitPacket(bridge, packet, request_length) == 0);
  if (!remote) {
    const uint64_t deadline = nowMilliseconds() + 30000U;
    while (atomic_load(&server.response_size) == 0 &&
           nowMilliseconds() < deadline) {
      usleep(1000);
    }
    const uint64_t expected = atomic_load(&server.response_size);
    CHECK(expected > 0);
    uint32_t acknowledged = peer_sequence + 1U;
    const uint32_t request_next_sequence =
        2U + (uint32_t)(request_length - 40U);
    while (atomic_load(&state.received_payload) < expected &&
           atomic_load(&state.failure) == 0 && nowMilliseconds() < deadline) {
      const uint32_t next = (uint32_t)atomic_load(&state.next_ack);
      if (next != acknowledged) {
        makeTcp(packet, state.destination_port, TH_ACK, request_next_sequence,
                next);
        const int result = SRPWaterWallBridgeSubmitPacket(bridge, packet, 40);
        static unsigned ack_attempts = 0;
        if (getenv("POC_TRACE_ACK") != NULL &&
            (ack_attempts < 10 || ack_attempts % 1000 == 0)) {
          fprintf(stderr, "ACK next=%u result=%d\n", next, result);
        }
        ack_attempts++;
        if (result == 0) {
          acknowledged = next;
        } else {
          CHECK(result == -EAGAIN || result == -ENOTCONN);
        }
      }
      usleep(1000);
    }
    fprintf(stderr, "received %llu of %llu response bytes\n",
            (unsigned long long)atomic_load(&state.received_payload),
            (unsigned long long)expected);
    CHECK(atomic_load(&state.received_payload) >= expected);
  }
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
