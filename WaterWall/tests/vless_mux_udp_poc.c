#include "SRPWaterWallBridge.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
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

typedef struct test_state_s {
  atomic_int ready;
  atomic_int failure;
  atomic_int response;
  atomic_int server_failure;
  int listen_fd;
  uint16_t port;
  pthread_t server_thread;
  uint16_t dns_id;
  uint16_t expected_response_id;
  uint16_t dns_port;
  atomic_uint_fast64_t query_started_at;
  atomic_uint_fast64_t total_rtt_ms;
  atomic_uint_fast64_t max_rtt_ms;
  atomic_uint_fast64_t previous_rtt_ms;
  atomic_uint_fast64_t total_jitter_ms;
} test_state_t;

static uint64_t nowMilliseconds(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return ((uint64_t)now.tv_sec * 1000U) + ((uint64_t)now.tv_nsec / 1000000U);
}

static void waitFor(atomic_int *value) {
  const uint64_t deadline = nowMilliseconds() + 10000U;
  while (atomic_load(value) == 0 && nowMilliseconds() < deadline) {
    usleep(10000);
  }
  CHECK(atomic_load(value) != 0);
}

static void readyCallback(void *context) {
  test_state_t *state = context;
  atomic_store(&state->ready, 1);
}

static void failureCallback(void *context, int code, const char *message) {
  fprintf(stderr, "runtime failure %d: %s\n", code,
          message != NULL ? message : "(no message)");
  test_state_t *state = context;
  atomic_store(&state->failure, code == 0 ? 1 : code);
}

static void logCallback(void *context, int level, const char *message,
                        size_t length) {
  (void)context;
  (void)level;
  fprintf(stderr, "%.*s\n", (int)length, message);
}

static void packetCallback(void *context, const uint8_t *packet,
                           size_t length) {
  test_state_t *state = context;
  if (length < 28 || (packet[0] >> 4) != 4 || packet[9] != 17) {
    return;
  }
  const size_t ihl = (packet[0] & 0x0fU) * 4U;
  if (length < ihl + 10 || ihl < 20 ||
      ntohs(*(const uint16_t *)(packet + ihl + 2)) != 5353) {
    return;
  }
  const uint8_t *dns = packet + ihl + 8;
  if (ntohs(*(const uint16_t *)(packet + ihl)) == state->dns_port &&
      ntohs(*(const uint16_t *)dns) == state->expected_response_id &&
      (dns[2] & 0x80U) != 0 && (dns[3] & 0x0fU) == 0) {
    const uint64_t rtt = nowMilliseconds() - atomic_load(&state->query_started_at);
    const unsigned previous_response = (unsigned)atomic_fetch_add(&state->response, 1);
    atomic_fetch_add(&state->total_rtt_ms, rtt);
    uint64_t maximum = atomic_load(&state->max_rtt_ms);
    while (maximum < rtt && !atomic_compare_exchange_weak(&state->max_rtt_ms, &maximum, rtt)) {
    }
    const uint64_t previous_rtt = atomic_exchange(&state->previous_rtt_ms, rtt);
    if (previous_response > 0) {
      atomic_fetch_add(&state->total_jitter_ms, rtt > previous_rtt ? rtt - previous_rtt : previous_rtt - rtt);
    }
  }
}

static void reportResults(test_state_t *state, unsigned expected, uint64_t started) {
  const unsigned responses = (unsigned)atomic_load(&state->response);
  fprintf(stderr, "UDP responses: %u of %u in %llu ms\n", responses, expected,
          (unsigned long long)(nowMilliseconds() - started));
  fprintf(stderr, "UDP timing: average_rtt_ms=%.3f max_rtt_ms=%llu average_jitter_ms=%.3f\n",
          responses > 0 ? (double)atomic_load(&state->total_rtt_ms) / responses : 0.0,
          (unsigned long long)atomic_load(&state->max_rtt_ms),
          responses > 1 ? (double)atomic_load(&state->total_jitter_ms) / (responses - 1) : 0.0);
  struct rusage usage = {0};
  if (getrusage(RUSAGE_SELF, &usage) == 0) {
#ifdef __APPLE__
    const unsigned long long max_rss_kib = (unsigned long long)usage.ru_maxrss / 1024U;
#else
    const unsigned long long max_rss_kib = (unsigned long long)usage.ru_maxrss;
#endif
    fprintf(stderr, "Resources: max_rss_kib=%llu user_cpu_ms=%llu system_cpu_ms=%llu\n", max_rss_kib,
            (unsigned long long)usage.ru_utime.tv_sec * 1000U + (unsigned long long)usage.ru_utime.tv_usec / 1000U,
            (unsigned long long)usage.ru_stime.tv_sec * 1000U + (unsigned long long)usage.ru_stime.tv_usec / 1000U);
  }
}

static int readExact(int fd, uint8_t *buffer, size_t length) {
  while (length != 0) {
    const ssize_t count = read(fd, buffer, length);
    if (count <= 0) {
      return -1;
    }
    buffer += count;
    length -= (size_t)count;
  }
  return 0;
}

static int writeExact(int fd, const uint8_t *buffer, size_t length) {
  while (length != 0) {
    const ssize_t count = write(fd, buffer, length);
    if (count <= 0) {
      return -1;
    }
    buffer += count;
    length -= (size_t)count;
  }
  return 0;
}

static uint32_t readU24(const uint8_t *bytes) {
  return ((uint32_t)bytes[0] << 16) | ((uint32_t)bytes[1] << 8) | bytes[2];
}

static void *serveMuxVlessUdp(void *argument) {
  test_state_t *state = argument;
  int fd = accept(state->listen_fd, NULL, NULL);
  if (fd < 0) {
    atomic_store(&state->server_failure, errno);
    return NULL;
  }
  const struct timeval timeout = {.tv_sec = 3};
  CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ==
        0);
  uint8_t header[8];
  uint8_t request[26];
  uint8_t size_bytes[2];
  uint8_t query[512];
  uint8_t response[512];
  size_t query_length = 0;
  do {
    if (readExact(fd, header, sizeof(header)) != 0 || readU24(header) != 0 ||
        header[3] != 0 || readExact(fd, header, sizeof(header)) != 0 ||
        header[3] != 4) {
      atomic_store(&state->server_failure, 1);
      break;
    }
    const uint32_t data_length = readU24(header);
    if (data_length < sizeof(request) + 2 ||
        data_length > sizeof(request) + 2 + sizeof(query)) {
      atomic_store(&state->server_failure, 2);
      break;
    }
    if (readExact(fd, request, sizeof(request)) != 0 || request[0] != 0 ||
        request[17] != 0 || request[18] != 2 || request[19] != 0 ||
        request[20] != 53 || request[21] != 1 || request[22] != 192 ||
        request[23] != 0 || request[24] != 2 || request[25] != 53 ||
        readExact(fd, size_bytes, 2) != 0) {
      atomic_store(&state->server_failure, 3);
      break;
    }
    query_length = ntohs(*(const uint16_t *)size_bytes);
    if (query_length > sizeof(query) ||
        data_length != sizeof(request) + 2 + query_length ||
        readExact(fd, query, query_length) != 0) {
      atomic_store(&state->server_failure, 4);
      break;
    }
    memcpy(response, query, query_length);
    if (query_length >= 12) {
      response[2] |= 0x80;
      response[3] |= 0x80;
    }
    const size_t vless_length = 2 + 2 + query_length;
    uint8_t output[8 + 4 + 512];
    output[0] = (uint8_t)(vless_length >> 16);
    output[1] = (uint8_t)(vless_length >> 8);
    output[2] = (uint8_t)vless_length;
    output[3] = 4;
    output[4] = output[5] = output[6] = 0;
    output[7] = 1;
    output[8] = output[9] = 0;
    const uint16_t query_size = htons((uint16_t)query_length);
    memcpy(output + 10, &query_size, 2);
    memcpy(output + 12, response, query_length);
    if (writeExact(fd, output, 12 + query_length) != 0) {
      break;
    }
    close(fd);
    return NULL;
  } while (0);
  close(fd);
  return NULL;
}

static uint16_t checksum(const uint8_t *bytes, size_t length) {
  uint32_t sum = 0;
  for (size_t i = 0; i + 1 < length; i += 2) {
    sum += ((uint32_t)bytes[i] << 8) | bytes[i + 1];
  }
  if ((length & 1U) != 0) {
    sum += (uint32_t)bytes[length - 1] << 8;
  }
  while (sum >> 16) {
    sum = (sum & 0xffffU) + (sum >> 16);
  }
  return (uint16_t)~sum;
}

static size_t makeDnsQuery(test_state_t *state, uint8_t *packet) {
  state->dns_id = htons(state->expected_response_id);
  uint8_t dns[12 + 13 + 4] = {0};
  memcpy(dns, &state->dns_id, 2);
  dns[2] = 1;
  dns[5] = 1;
  memcpy(dns + 12, "\x07example\x03com\x00\x00\x01\x00\x01", 17);
  const size_t dns_length = sizeof(dns);
  memset(packet, 0, 28);
  packet[0] = 0x45;
  packet[2] = (uint8_t)((28 + dns_length) >> 8);
  packet[3] = (uint8_t)(28 + dns_length);
  packet[8] = 64;
  packet[9] = 17;
  packet[12] = 10;
  packet[15] = 2;
  if (getenv("POC_SOURCE_IP") != NULL) {
    CHECK(inet_pton(AF_INET, getenv("POC_SOURCE_IP"), packet + 12) == 1);
  }
  if (getenv("POC_DNS_IP") != NULL) {
    CHECK(inet_pton(AF_INET,
                    getenv("POC_DNS_IP") != NULL ? getenv("POC_DNS_IP")
                                                 : "127.0.0.1",
                    packet + 16) == 1);
  } else {
    packet[16] = 192;
    packet[18] = 2;
    packet[19] = 53;
  }
  const uint16_t source_port = htons(5353);
  const uint16_t dest_port = htons(state->dns_port);
  const uint16_t udp_length = htons((uint16_t)(8 + dns_length));
  memcpy(packet + 20, &source_port, 2);
  memcpy(packet + 22, &dest_port, 2);
  memcpy(packet + 24, &udp_length, 2);
  memcpy(packet + 28, dns, dns_length);
  const uint16_t ip_checksum = htons(checksum(packet, 20));
  memcpy(packet + 10, &ip_checksum, 2);
  return 28 + dns_length;
}

static void startServer(test_state_t *state) {
  state->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  CHECK(state->listen_fd >= 0);
  int reuse = 1;
  CHECK(setsockopt(state->listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse,
                   sizeof(reuse)) == 0);
  const struct timeval timeout = {.tv_sec = 3};
  CHECK(setsockopt(state->listen_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) == 0);
  struct sockaddr_in address = {.sin_family = AF_INET,
                                .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  CHECK(bind(state->listen_fd, (struct sockaddr *)&address, sizeof(address)) ==
        0);
  socklen_t address_length = sizeof(address);
  CHECK(getsockname(state->listen_fd, (struct sockaddr *)&address,
                    &address_length) == 0);
  state->port = ntohs(address.sin_port);
  CHECK(listen(state->listen_fd, 1) == 0);
  CHECK(pthread_create(&state->server_thread, NULL, serveMuxVlessUdp, state) ==
        0);
}

int main(void) {
  test_state_t state = {0};
  const bool bgp4 = getenv("POC_BGP4") != NULL;
  const bool kcp = bgp4 && getenv("POC_BGP4_KCP") != NULL;
  const char *config_path = getenv("POC_REMOTE_CONFIG");
  const bool remote = config_path != NULL;
  state.dns_port = 53;
  if (remote) {
    const char *peer = getenv("POC_REMOTE_PORT");
    CHECK(peer != NULL);
    const long port = strtol(peer, NULL, 10);
    CHECK(port > 0 && port <= 65535);
    state.port = (uint16_t)port;
  } else if (bgp4) {
    const char *peer = getenv("POC_BGP4_PORT");
    CHECK(peer != NULL);
    const long port = strtol(peer, NULL, 10);
    CHECK(port > 0 && port <= 65535);
    state.port = (uint16_t)port;
    const char *dns = getenv("POC_DNS_PORT");
    CHECK(dns != NULL);
    const long dns_port = strtol(dns, NULL, 10);
    CHECK(dns_port > 0 && dns_port <= 65535);
    state.dns_port = (uint16_t)dns_port;
  } else {
    startServer(&state);
  }
  if (getenv("POC_DNS_PORT") != NULL) {
    const long dns_port = strtol(getenv("POC_DNS_PORT"), NULL, 10);
    CHECK(dns_port > 0 && dns_port <= 65535);
    state.dns_port = (uint16_t)dns_port;
  }
  char nodes[32768];
  const char *router =
      bgp4 ? "{\"name\":\"router\",\"type\":\"Router\",\"settings\":{"
             "\"resolve-domains\":false},\"next\":\"vless\"},"
           : "";
  const char *outer =
      bgp4 ? "{\"name\":\"bgp4\",\"type\":\"Bgp4Client\",\"settings\":{},"
             "\"next\":\"%s\"},%s"
           : "{\"name\":\"mux\",\"type\":\"MuxClient\",\"settings\":{"
             "\"mode\":\"counter\",\"connection-capacity\":1},"
             "\"next\":\"out\"},";
  char outer_json[512];
  if (bgp4) {
    snprintf(outer_json, sizeof(outer_json), outer, kcp ? "kcp" : "out",
             kcp ? "{\"name\":\"kcp\",\"type\":\"TcpOverUdpClient\","
                   "\"settings\":{},\"next\":\"out\"},"
                 : "");
  } else {
    snprintf(outer_json, sizeof(outer_json), "%s", outer);
  }
  int count;
  if (config_path != NULL) {
    FILE *config = fopen(config_path, "rb");
    CHECK(config != NULL);
    count = (int)fread(nodes, 1, sizeof(nodes) - 1, config);
    fclose(config);
    CHECK(count > 0 && (size_t)count < sizeof(nodes) - 1);
    nodes[count] = '\0';
  } else {
    count = snprintf(
        nodes, sizeof(nodes),
        "{\"name\":\"vless-udp\",\"nodes\":["
        "{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"settings\":{},"
        "\"next\":\"ptc\"},"
        "{\"name\":\"ptc\",\"type\":\"PacketsToConnection\","
        "\"settings\":{\"fake-dns\":{\"enabled\":true}},\"next\":\"%s\"},"
        "%s"
        "{\"name\":\"vless\",\"type\":\"VlessClient\",\"settings\":{"
        "\"uuid\":\"00112233-4455-6677-8899-aabbccddeeff\",\"address\":"
        "\"%s\",\"port\":%u,"
        "\"protocol\":\"%s\",\"verbose\":true,\"domain-strategy\":\"do-not-"
        "resolve-"
        "domains\"},\"next\":\"%s\"},%s"
        "{\"name\":\"out\",\"type\":\"%s\",\"settings\":{"
        "\"address\":\"127.0.0.1\",\"port\":%u,"
        "\"nodelay\":true}}]}",
        bgp4 ? "router" : "vless", router,
        getenv("POC_DNS_IP") != NULL ? getenv("POC_DNS_IP")
                                     : (bgp4 ? "127.0.0.1" : "192.0.2.53"),
        (unsigned int)state.dns_port, bgp4 ? "dest_context->protocol" : "udp",
        bgp4 ? "bgp4" : "mux", outer_json,
        kcp ? "UdpConnector" : "TcpUdpConnector", (unsigned int)state.port);
  }
  CHECK(count > 0 && (size_t)count < sizeof(nodes));
  SRPWaterWallCallbacks callbacks = {.packet = packetCallback,
                                     .log = logCallback,
                                     .ready = readyCallback,
                                     .failure = failureCallback,
                                     .context = &state};
  SRPWaterWallConfig config = {
      .core_json =
          getenv("POC_MINIMAL") != NULL
              ? "{\"log\":{\"network\":{\"loglevel\":\"DEBUG\","
                "\"console\":true}},\"misc\":{\"workers\":1,"
                "\"ram-profile\":\"minimal\",\"splice\":false,"
                "\"try-enabling-bbr\":false,\"tcp-tune\":false},"
                "\"configs\":[\"hosted-nodes.json\"]}"
              : "{\"log\":{\"network\":{\"loglevel\":\"DEBUG\","
                "\"console\":true}},\"configs\":[\"hosted-nodes.json\"]}",
      .nodes_json = nodes};
  SRPWaterWallBridge *bridge = SRPWaterWallBridgeStart(&config, &callbacks);
  CHECK(bridge != NULL);
  waitFor(&state.ready);
  CHECK(atomic_load(&state.failure) == 0);
  const uint64_t duration =
      getenv("POC_UDP_DURATION") != NULL
          ? strtoull(getenv("POC_UDP_DURATION"), NULL, 10)
          : 0;
  CHECK(duration <= 3600);
  unsigned expected_responses = duration > 0 ? (unsigned)duration * 10U : 1;
  if (remote && getenv("POC_UDP_REPEAT") != NULL && duration == 0) {
    const long repeat = strtol(getenv("POC_UDP_REPEAT"), NULL, 10);
    CHECK(repeat >= 1 && repeat <= 64);
    expected_responses = (unsigned)repeat;
  }
  const uint64_t started = nowMilliseconds();
  uint8_t packet[128];
  for (unsigned i = 0; i < expected_responses; ++i) {
    atomic_store(&state.query_started_at, nowMilliseconds());
    state.expected_response_id = (uint16_t)(i + 1);
    const size_t packet_length = makeDnsQuery(&state, packet);
    const uint64_t deadline = nowMilliseconds() + 10000U;
    uint64_t next_send = nowMilliseconds();
    while (atomic_load(&state.response) < (int)(i + 1) &&
           atomic_load(&state.server_failure) == 0 &&
           nowMilliseconds() < deadline) {
      if (nowMilliseconds() >= next_send) {
        const int result = SRPWaterWallBridgeSubmitPacket(bridge, packet, packet_length);
        CHECK(result == 0 || result == -EAGAIN || result == -ENOTCONN);
        next_send = nowMilliseconds() + 200U;
      }
      usleep(10000);
    }
    if (atomic_load(&state.response) < (int)(i + 1) && atomic_load(&state.server_failure) == 0) {
      reportResults(&state, expected_responses, started);
      CHECK(SRPWaterWallBridgeStop(bridge) == 0);
      return 1;
    }
    if (duration > 0) {
      const uint64_t target = started + (uint64_t)(i + 1) * 100U;
      const uint64_t remaining = target > nowMilliseconds() ? target - nowMilliseconds() : 0;
      if (remaining > 0) {
        usleep((useconds_t)remaining * 1000U);
      }
    }
  }
  CHECK(nowMilliseconds() - started >= duration * 1000U);
  reportResults(&state, expected_responses, started);
  if (!remote && !bgp4) {
    CHECK(pthread_join(state.server_thread, NULL) == 0);
  }
  CHECK(atomic_load(&state.server_failure) == 0);
  CHECK(atomic_load(&state.response) >= (int)expected_responses);
  CHECK(SRPWaterWallBridgeStop(bridge) == 0);
  if (!remote && !bgp4) {
    close(state.listen_fd);
  }
  fprintf(stderr, "%s native UDP response passed\n",
          bgp4 ? "BGP4 VLESS" : "VLESS MUX");
  return 0;
}
