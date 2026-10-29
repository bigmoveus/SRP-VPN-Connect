#include "SRPWaterWallBridge.h"
#include "PacketsToConnection/structure.h"

#include "libc/wlibc.h"

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
#include <sys/resource.h>
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

#define POC_MAX_CONNECTIONS 16

typedef struct poc_flow_s {
  atomic_int syn_ack;
  atomic_int http_response;
  atomic_uint_fast64_t next_ack;
  atomic_uint_fast64_t received_payload;
  uint8_t syn_ack_sequence[4];
  uint8_t http_header[5];
  uint8_t http_header_size;
} poc_flow_t;

typedef struct poc_state_s {
  atomic_int ready;
  atomic_int failure;
  atomic_int packets;
  atomic_int out_of_order;
  atomic_int fake_dns_ready;
  uint8_t fake_ip[4];
  uint16_t destination_port;
  size_t connection_count;
  poc_flow_t flows[POC_MAX_CONNECTIONS];
} poc_state_t;

typedef struct server_state_s {
  int fd;
  pthread_t thread;
  pthread_t workers[POC_MAX_CONNECTIONS];
  atomic_int accepted;
  atomic_uint_fast64_t response_size;
  atomic_uint_fast64_t sent_payload;
  uint16_t port;
  size_t connection_count;
} server_state_t;

typedef struct client_state_s {
  server_state_t *server;
  int fd;
} client_state_t;

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
  if (getenv("POC_FAKE_DNS_NAME") != NULL && length >= 45 &&
      packet[0] == 0x45 && packet[9] == IPPROTO_UDP &&
      packet[20] == 0 && packet[21] == 53 &&
      packet[22] == (12353 >> 8) && packet[23] == (12353 & 0xff) &&
      packet[28] == 0x42 && packet[29] == 0x43 &&
      (packet[30] & 0x80U) != 0 && packet[32] == 0 &&
      packet[33] == 1 && packet[34] == 0 && packet[35] == 1) {
    memcpy(state->fake_ip, packet + length - 4, 4);
    atomic_store(&state->fake_dns_ready, 1);
  }
  if (length >= 40 && packet[0] == 0x45 && packet[9] == IPPROTO_TCP) {
    const uint8_t *tcp = packet + 20;
    uint16_t source;
    uint16_t destination;
    memcpy(&source, tcp, sizeof(source));
    memcpy(&destination, tcp + 2, sizeof(destination));
    if (source != htons(state->destination_port) ||
        ntohs(destination) < 12345 ||
        ntohs(destination) >= 12345 + state->connection_count) {
      return;
    }
    poc_flow_t *flow = &state->flows[ntohs(destination) - 12345];
    if ((tcp[13] & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
      memcpy(flow->syn_ack_sequence, tcp + 4, sizeof(flow->syn_ack_sequence));
      atomic_store(&flow->syn_ack, 1);
    }
    const size_t payload_offset = 20 + ((tcp[12] >> 4) * 4);
    if (length >= payload_offset) {
      const size_t payload_length = length - payload_offset;
      if (payload_length > 0) {
        uint32_t sequence;
        memcpy(&sequence, tcp + 4, sizeof(sequence));
        const uint32_t next = ntohl(sequence) + (uint32_t)payload_length +
                              ((tcp[13] & TH_FIN) != 0 ? 1U : 0U);
        const uint32_t expected = (uint32_t)atomic_load(&flow->next_ack);
        if (getenv("POC_DEBUG") != NULL && atomic_load(&state->packets) < 20) {
          fprintf(stderr, "payload seq=%u expected=%u len=%zu first=", ntohl(sequence), expected, payload_length);
          for (size_t i = 0; i < payload_length && i < 16; ++i) {
            fprintf(stderr, "%02x", packet[payload_offset + i]);
          }
          fprintf(stderr, "\n");
        }
        if (getenv("POC_TRACE_TCP") != NULL && ntohl(sequence) > expected &&
            atomic_fetch_add(&state->out_of_order, 1) < 20) {
          fprintf(stderr, "TCP gap: sequence=%u expected=%u payload=%zu next=%u\n",
                  ntohl(sequence), expected, payload_length, next);
        }
        if (ntohl(sequence) <= expected && next > expected) {
          atomic_fetch_add(&flow->received_payload, next - expected);
          uint_fast64_t previous = expected;
          while (previous < next && !atomic_compare_exchange_weak(
                                        &flow->next_ack, &previous, next)) {
          }
          for (size_t i = 0; i < payload_length && flow->http_header_size < 5;
               ++i) {
            flow->http_header[flow->http_header_size++] =
                packet[payload_offset + i];
          }
        }
        if (flow->http_header_size == 5 &&
            memcmp(flow->http_header, "HTTP/", 5) == 0) {
          atomic_store(&flow->http_response, 1);
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

static void waitForCountImpl(atomic_int *value, int expected, const char *name) {
  const uint64_t deadline = nowMilliseconds() + 15000U;
  while (atomic_load(value) < expected && nowMilliseconds() < deadline) {
    usleep(10000);
  }
  fprintf(stderr, "wait %s = %d/%d\n", name, atomic_load(value), expected);
  CHECK(atomic_load(value) >= expected);
}

#define waitFor(value) waitForCountImpl(value, 1, #value)
#define waitForCount(value, count) waitForCountImpl(value, count, #value)

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

static void *serveClient(void *context) {
  client_state_t *client = context;
  server_state_t *server = client->server;
  const int fd = client->fd;
  free(client);
  char request[1024];
  size_t received = 0;
  while (memmem(request, received, "GET /", 5) == NULL) {
    CHECK(received < sizeof(request));
    const ssize_t count = read(fd, request + received, sizeof(request) - received);
    CHECK(count > 0);
    received += (size_t)count;
  }
  const char *stress = getenv("POC_STRESS_BYTES");
  uint64_t body_size = stress != NULL ? strtoull(stress, NULL, 10) : 0;
  const uint64_t duration =
      getenv("POC_STRESS_DURATION") != NULL
          ? strtoull(getenv("POC_STRESS_DURATION"), NULL, 10)
          : 0;
  const uint64_t bytes_per_second =
      getenv("POC_SERVER_BPS") != NULL
          ? strtoull(getenv("POC_SERVER_BPS"), NULL, 10)
          : 1048576;
  CHECK(duration <= 3600 && bytes_per_second >= 1024 &&
        bytes_per_second <= 67108864);
  if (duration > 0) {
    body_size = duration * bytes_per_second;
  }
  CHECK(body_size <= 128U * 1024U * 1024U);
  char response[160];
  const int header_length = snprintf(
      response, sizeof(response),
      "HTTP/1.1 200 OK\r\nContent-Length: %llu\r\nConnection: close\r\n\r\n",
      (unsigned long long)body_size);
  CHECK(header_length > 0 && (size_t)header_length < sizeof(response));
  atomic_store(&server->response_size, (uint64_t)header_length + body_size);
  writeAll(fd, (const uint8_t *)response, (size_t)header_length);
  atomic_fetch_add(&server->sent_payload, (uint64_t)header_length);
  uint8_t body[16384] = {0};
  const uint64_t send_started = nowMilliseconds();
  for (uint64_t offset = 0; offset < body_size; offset += sizeof(body)) {
    const size_t size =
        (size_t)(body_size - offset < sizeof(body) ? body_size - offset
                                                   : sizeof(body));
    if (duration > 0) {
      const uint64_t target = send_started + ((offset + size) * 1000U) / bytes_per_second;
      const uint64_t now = nowMilliseconds();
      if (target > now) {
        const uint64_t remaining = target - now;
        struct timespec delay = {.tv_sec = (time_t)(remaining / 1000U),
                                 .tv_nsec = (long)((remaining % 1000U) * 1000000U)};
        int result;
        do {
          result = nanosleep(&delay, &delay);
        } while (result != 0 && errno == EINTR);
        CHECK(result == 0);
      }
    }
    writeAll(fd, body, size);
    atomic_fetch_add(&server->sent_payload, size);
  }
  if (getenv("POC_TRACE_PACING") != NULL) {
    fprintf(stderr, "Server pacing: %llu bytes in %llu ms; target %llu ms\n",
            (unsigned long long)body_size, (unsigned long long)(nowMilliseconds() - send_started),
            (unsigned long long)((body_size * 1000U) / bytes_per_second));
  }
  close(fd);
  return NULL;
}

static void *acceptConnections(void *context) {
  server_state_t *server = context;
  for (size_t index = 0; index < server->connection_count; ++index) {
    const int fd = accept(server->fd, NULL, NULL);
    CHECK(fd >= 0);
    client_state_t *client = calloc(1, sizeof(*client));
    CHECK(client != NULL);
    client->server = server;
    client->fd = fd;
    atomic_fetch_add(&server->accepted, 1);
    CHECK(pthread_create(&server->workers[index], NULL, serveClient, client) == 0);
  }
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
  CHECK(listen(server->fd, POC_MAX_CONNECTIONS) == 0);
  CHECK(getsockname(server->fd, (struct sockaddr *)&address, &length) == 0);
  server->port = ntohs(address.sin_port);
  server->connection_count = getenv("POC_CONNECTIONS") != NULL
      ? strtoul(getenv("POC_CONNECTIONS"), NULL, 10) : 1;
  CHECK(server->connection_count >= 1 &&
        server->connection_count <= POC_MAX_CONNECTIONS);
  char bound_address[INET_ADDRSTRLEN];
  CHECK(inet_ntop(AF_INET, &address.sin_addr, bound_address, sizeof(bound_address)) != NULL);
  fprintf(stderr, "HTTP listener: %s:%u\n", bound_address, server->port);
  CHECK(pthread_create(&server->thread, NULL, acceptConnections, server) == 0);
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

static void queryFakeDns(SRPWaterWallBridge *bridge, poc_state_t *state) {
  const char *domain = getenv("POC_FAKE_DNS_NAME");
  CHECK(domain != NULL);
  const size_t domain_length = strlen(domain);
  CHECK(domain_length > 0 && domain_length <= 253);
  uint8_t packet[128] = {0};
  const size_t packet_length = 46 + domain_length;
  packet[0] = 0x45;
  packet[2] = (uint8_t)(packet_length >> 8);
  packet[3] = (uint8_t)packet_length;
  packet[8] = 64;
  packet[9] = IPPROTO_UDP;
  packet[12] = 10;
  packet[15] = 2;
  packet[16] = 198;
  packet[17] = 18;
  packet[18] = 0;
  packet[19] = 2;
  const uint16_t ip_sum = checksum(packet, 20);
  packet[10] = (uint8_t)(ip_sum >> 8);
  packet[11] = (uint8_t)ip_sum;
  const uint16_t udp_length = htons((uint16_t)(packet_length - 20));
  memcpy(packet + 20, &(uint16_t){htons(12353)}, 2);
  memcpy(packet + 22, &(uint16_t){htons(53)}, 2);
  memcpy(packet + 24, &udp_length, 2);
  packet[28] = 0x42;
  packet[29] = 0x43;
  packet[30] = 1;
  packet[33] = 1;
  size_t offset = 40;
  const char *label = domain;
  for (size_t index = 0; index <= domain_length; ++index) {
    if (domain[index] != '.' && domain[index] != '\0') continue;
    const size_t length = (size_t)(domain + index - label);
    CHECK(length > 0 && length <= 63);
    packet[offset++] = (uint8_t)length;
    memcpy(packet + offset, label, length);
    offset += length;
    label = domain + index + 1;
  }
  packet[offset++] = 0;
  packet[offset++] = 0;
  packet[offset++] = 1;
  packet[offset++] = 0;
  packet[offset++] = 1;
  CHECK(offset == packet_length);
  const uint64_t deadline = nowMilliseconds() + 5000U;
  uint64_t next_send = 0;
  while (!atomic_load(&state->fake_dns_ready) && nowMilliseconds() < deadline) {
    if (nowMilliseconds() >= next_send) {
      const int result = SRPWaterWallBridgeSubmitPacket(bridge, packet, packet_length);
      CHECK(result == 0 || result == -EAGAIN || result == -ENOTCONN);
      next_send = nowMilliseconds() + 200U;
    }
    usleep(10000);
  }
  CHECK(atomic_load(&state->fake_dns_ready));
  char mapped[INET_ADDRSTRLEN];
  CHECK(inet_ntop(AF_INET, state->fake_ip, mapped, sizeof(mapped)) != NULL);
  fprintf(stderr, "Fake DNS mapped %s to %s\n", domain, mapped);
  CHECK(setenv("POC_REMOTE_IP", mapped, 1) == 0);
}

static void makeTcp(uint8_t packet[40], uint16_t destination_port,
                    uint8_t flags, uint32_t sequence,
                    uint32_t acknowledgement, uint16_t source_port) {
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
  if (getenv("POC_SOURCE_IP") != NULL) {
    CHECK(inet_pton(AF_INET, getenv("POC_SOURCE_IP"), packet + 12) == 1);
  }
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
  tcp[0] = (uint8_t)(source_port >> 8);
  tcp[1] = (uint8_t)source_port;
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
                              uint32_t acknowledgement, uint16_t source_port) {
  char request[512];
  const char *path = getenv("POC_HTTP_PATH");
  const int length = snprintf(request, sizeof(request),
                              "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                              path != NULL ? path : "/");
  CHECK(length > 0 && (size_t)length < sizeof(request));
  const size_t payload_length = (size_t)length;
  const size_t packet_length = 40 + payload_length;
  makeTcp(packet, destination_port, TH_ACK | TH_PUSH, 2, acknowledgement, source_port);
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
            "\"network\":{\"loglevel\":\"DEBUG\",\"console\":true},"
            "\"dns\":{\"loglevel\":\"DEBUG\",\"console\":true}},"
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

static void reportResources(void) {
  struct rusage usage = {0};
  if (getrusage(RUSAGE_SELF, &usage) != 0) {
    return;
  }
#ifdef __APPLE__
  const unsigned long long max_rss_kib = (unsigned long long)usage.ru_maxrss / 1024U;
#else
  const unsigned long long max_rss_kib = (unsigned long long)usage.ru_maxrss;
#endif
  fprintf(stderr, "Resources: max_rss_kib=%llu user_cpu_ms=%llu system_cpu_ms=%llu\n", max_rss_kib,
          (unsigned long long)usage.ru_utime.tv_sec * 1000U + (unsigned long long)usage.ru_utime.tv_usec / 1000U,
          (unsigned long long)usage.ru_stime.tv_sec * 1000U + (unsigned long long)usage.ru_stime.tv_usec / 1000U);
}

static void testTcpAggregateBudget(void) {
  ptc_tstate_t state = {.max_pending_bytes = 65536,
                        .max_total_pending_bytes = 131072};
  bool first = false;
  bool second = false;
  bool third = false;
  bool draining = false;
  CHECK(ptcTcpBudgetReserve(&state));
  first = true;
  CHECK(ptcTcpBudgetReserve(&state));
  second = true;
  CHECK(!ptcTcpBudgetReserve(&state));
  ptcTcpBudgetTransfer(&first, &draining);
  CHECK(!first && draining);
  ptcTcpBudgetRelease(&state, &second);
  CHECK(ptcTcpBudgetReserve(&state));
  third = true;
  ptcTcpBudgetRelease(&state, &third);
  ptcTcpBudgetRelease(&state, &draining);
  CHECK(atomic_load(&state.tcp_reserved_bytes) == 0);
  puts("TCP aggregate budget passed");
}

int main(void) {
  testTcpAggregateBudget();
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
  state.connection_count = getenv("POC_CONNECTIONS") != NULL
      ? strtoul(getenv("POC_CONNECTIONS"), NULL, 10) : 1;
  CHECK(state.connection_count >= 1 && state.connection_count <= POC_MAX_CONNECTIONS);
  SRPWaterWallBridge *bridge = NULL;
  if (getenv("POC_SKIP_INVALID") == NULL) {
    bridge = startRuntime(&state, invalid_nodes);
    waitFor(&state.failure);
    CHECK(SRPWaterWallBridgeStop(bridge) == 0);
  }

  server_state_t server = {0};
  const bool remote = getenv("POC_REMOTE_IP") != NULL;
  const bool external_http = getenv("POC_EXTERNAL_HTTP") != NULL;
  const bool has_server = !remote || getenv("POC_RAW_TRANSPORT") != NULL || external_http;
  if (has_server && !external_http) {
    startServer(&server);
  }
  if (external_http) {
    const char *bytes = getenv("POC_STRESS_BYTES");
    atomic_store(&server.response_size, bytes != NULL ? strtoull(bytes, NULL, 10) : 16777216U);
  }
  const char *remote_port = getenv("POC_REMOTE_PORT");
  CHECK(!remote || remote_port != NULL);
  state.destination_port = remote ? atoi(remote_port) : server.port;
  CHECK(state.destination_port > 0);
  atomic_store(&state.failure, 0);
  const uint64_t tunnel_started = nowMilliseconds();
  bridge = startRuntime(&state, nodes);
  waitFor(&state.ready);
  fprintf(stderr, "Tunnel ready: %llu ms\n", (unsigned long long)(nowMilliseconds() - tunnel_started));
  if (getenv("POC_FAKE_DNS_NAME") != NULL) {
    queryFakeDns(bridge, &state);
  }

  uint8_t packet[512];
  uint32_t request_next_sequence[POC_MAX_CONNECTIONS];
  uint32_t acknowledged[POC_MAX_CONNECTIONS];
  for (size_t index = 0; index < state.connection_count; ++index) {
    poc_flow_t *flow = &state.flows[index];
    const uint16_t source_port = (uint16_t)(12345 + index);
    makeTcp(packet, state.destination_port, TH_SYN, 1, 0, source_port);
    const uint64_t syn_deadline = nowMilliseconds() + 15000U;
    do {
      const int result = SRPWaterWallBridgeSubmitPacket(bridge, packet, 40);
      CHECK(result == 0 || result == -EAGAIN || result == -ENOTCONN);
      for (unsigned wait = 0; wait < 20 && !atomic_load(&flow->syn_ack); ++wait) {
        usleep(10000);
      }
    } while (!atomic_load(&flow->syn_ack) && nowMilliseconds() < syn_deadline);
    CHECK(atomic_load(&flow->syn_ack));
    if (index == 0) {
      CHECK(SRPWaterWallBridgeSubmitPacket(bridge, packet, 1) == -EINVAL);
    }
    const uint32_t peer_sequence = ((uint32_t)flow->syn_ack_sequence[0] << 24) |
                                   ((uint32_t)flow->syn_ack_sequence[1] << 16) |
                                   ((uint32_t)flow->syn_ack_sequence[2] << 8) |
                                   flow->syn_ack_sequence[3];
    makeTcp(packet, state.destination_port, TH_ACK, 2, peer_sequence + 1U, source_port);
    CHECK(SRPWaterWallBridgeSubmitPacket(bridge, packet, 40) == 0);
    if (has_server && !external_http) {
      waitForCount(&server.accepted, (int)(index + 1));
    }
    const size_t request_length =
        makeHttpRequest(packet, state.destination_port, peer_sequence + 1U, source_port);
    atomic_store(&flow->next_ack, peer_sequence + 1U);
    CHECK(SRPWaterWallBridgeSubmitPacket(bridge, packet, request_length) == 0);
    request_next_sequence[index] = 2U + (uint32_t)(request_length - 40U);
    acknowledged[index] = peer_sequence + 1U;
  }
  if (has_server) {
    const uint64_t started = nowMilliseconds();
    const uint64_t duration =
        getenv("POC_STRESS_DURATION") != NULL
            ? strtoull(getenv("POC_STRESS_DURATION"), NULL, 10)
            : 0;
    CHECK(duration <= 3600);
    const uint64_t deadline = started + duration * 1000U + 30000U;
    while (atomic_load(&server.response_size) == 0 &&
           nowMilliseconds() < deadline) {
      usleep(1000);
    }
    const uint64_t expected = atomic_load(&server.response_size) * state.connection_count;
    CHECK(expected > 0);
    for (;;) {
      uint64_t received = 0;
      for (size_t index = 0; index < state.connection_count; ++index) {
        received += atomic_load(&state.flows[index].received_payload);
      }
      if (received >= expected || atomic_load(&state.failure) != 0 ||
          nowMilliseconds() >= deadline) {
        break;
      }
      for (size_t index = 0; index < state.connection_count; ++index) {
        const uint32_t next = (uint32_t)atomic_load(&state.flows[index].next_ack);
        if (next == acknowledged[index]) {
          continue;
        }
        const uint16_t source_port = (uint16_t)(12345 + index);
        makeTcp(packet, state.destination_port, TH_ACK, request_next_sequence[index],
                next, source_port);
        const int result = SRPWaterWallBridgeSubmitPacket(bridge, packet, 40);
        static unsigned ack_attempts = 0;
        if (getenv("POC_TRACE_ACK") != NULL &&
            (ack_attempts < 10 || ack_attempts % 1000 == 0)) {
          fprintf(stderr, "ACK flow=%zu next=%u result=%d\n", index, next, result);
        }
        ack_attempts++;
        if (result == 0) {
          acknowledged[index] = next;
        } else {
          CHECK(result == -EAGAIN || result == -ENOTCONN);
        }
      }
      usleep(1000);
    }
    const uint64_t elapsed = nowMilliseconds() - started;
    uint64_t received = 0;
    for (size_t index = 0; index < state.connection_count; ++index) {
      const uint64_t flow_received = atomic_load(&state.flows[index].received_payload);
      received += flow_received;
      fprintf(stderr, "flow %zu received %llu bytes\n", index + 1,
              (unsigned long long)flow_received);
    }
    fprintf(stderr, "received %llu of %llu response bytes in %llu ms; server sent %llu bytes\n",
            (unsigned long long)received, (unsigned long long)expected,
            (unsigned long long)elapsed,
            (unsigned long long)atomic_load(&server.sent_payload));
    CHECK(received >= expected);
    CHECK(elapsed >= duration * 1000U);
  }
  for (size_t index = 0; index < state.connection_count; ++index) {
    waitFor(&state.flows[index].http_response);
  }
  CHECK(atomic_load(&state.failure) == 0);
  CHECK(SRPWaterWallBridgeStop(bridge) == 0);
  if (has_server && !external_http) {
    CHECK(pthread_join(server.thread, NULL) == 0);
    for (size_t index = 0; index < server.connection_count; ++index) {
      CHECK(pthread_join(server.workers[index], NULL) == 0);
    }
    close(server.fd);
  }

  atomic_store(&state.ready, 0);
  bridge = startRuntime(&state, nodes);
  waitFor(&state.ready);
  CHECK(requestProgramShutdown(0));
  waitFor(&state.failure);
  CHECK(SRPWaterWallBridgeStop(bridge) == 0);

  atomic_store(&state.ready, 0);
  atomic_store(&state.failure, 0);
  bridge = startRuntime(&state, nodes);
  waitFor(&state.ready);
  CHECK(SRPWaterWallBridgeStop(bridge) == 0);
  CHECK(atomic_load(&state.failure) == 0);
  reportResources();
  puts("host PoC passed");
  return 0;
}
