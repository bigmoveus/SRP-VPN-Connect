#include "SRPWaterWallBridge.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
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

static void packetCallback(void *context, const uint8_t *packet,
                           size_t length) {
  (void)context;
  (void)packet;
  (void)length;
}

typedef struct chain_state_s {
  atomic_int ready;
  atomic_int failure;
} chain_state_t;

static void readyCallback(void *context) {
  chain_state_t *state = context;
  atomic_store(&state->ready, 1);
}

static void failureCallback(void *context, int code, const char *message) {
  (void)message;
  chain_state_t *state = context;
  atomic_store(&state->failure, code == 0 ? 1 : code);
}

static void logCallback(void *context, int level, const char *message,
                        size_t length) {
  (void)context;
  (void)level;
  fprintf(stderr, "%.*s\n", (int)length, message);
}

static uint64_t nowMilliseconds(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return ((uint64_t)now.tv_sec * 1000U) + ((uint64_t)now.tv_nsec / 1000000U);
}

static void waitFor(atomic_int *value) {
  const uint64_t deadline = nowMilliseconds() + 20000U;
  while (atomic_load(value) == 0 && nowMilliseconds() < deadline) {
    usleep(10000);
  }
  CHECK(atomic_load(value) != 0);
}

static void checkChain(const char *name, const char *nodes_json) {
  chain_state_t state = {0};
  SRPWaterWallCallbacks callbacks = {.packet = packetCallback,
                                     .log = logCallback,
                                     .ready = readyCallback,
                                     .failure = failureCallback,
                                     .context = &state};
  SRPWaterWallConfig config = {.core_json = NULL, .nodes_json = nodes_json};
  SRPWaterWallBridge *bridge = SRPWaterWallBridgeStart(&config, &callbacks);
  CHECK(bridge != NULL);
  waitFor(&state.ready);
  CHECK(atomic_load(&state.failure) == 0);
  CHECK(SRPWaterWallBridgeStop(bridge) == 0);
  fprintf(stderr, "%s startup/stop passed\n", name);
}

int main(void) {
  static const char vless[] =
      "{\"name\":\"vless\",\"nodes\":["
      "{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"settings\":{},\"next\":"
      "\"ptc\"},"
      "{\"name\":\"ptc\",\"type\":\"PacketsToConnection\",\"settings\":{},"
      "\"next\":\"vless\"},"
      "{\"name\":\"vless\",\"type\":\"VlessClient\",\"settings\":{"
      "\"uuid\":\"00112233-4455-6677-8899-aabbccddeeff\",\"address\":\"example."
      "com\",\"port\":80,"
      "\"protocol\":\"tcp\",\"domain-strategy\":\"do-not-resolve-domains\"},"
      "\"next\":\"tls\"},"
      "{\"name\":\"tls\",\"type\":\"TlsClient\",\"settings\":{\"sni\":"
      "\"localhost\",\"verify\":false},"
      "\"next\":\"out\"},"
      "{\"name\":\"out\",\"type\":\"TcpConnector\",\"settings\":{\"address\":"
      "\"127.0.0.1\",\"port\":9}}]}";
  static const char trojan[] =
      "{\"name\":\"trojan\",\"nodes\":["
      "{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"settings\":{},\"next\":"
      "\"ptc\"},"
      "{\"name\":\"ptc\",\"type\":\"PacketsToConnection\",\"settings\":{},"
      "\"next\":\"trojan\"},"
      "{\"name\":\"trojan\",\"type\":\"TrojanClient\",\"settings\":{"
      "\"password\":\"native-poc-placeholder\",\"address\":\"example.com\","
      "\"port\":80,"
      "\"protocol\":\"tcp\",\"domain-strategy\":\"do-not-resolve-domains\"},"
      "\"next\":\"tls\"},"
      "{\"name\":\"tls\",\"type\":\"TlsClient\",\"settings\":{\"sni\":"
      "\"localhost\",\"verify\":false},"
      "\"next\":\"out\"},"
      "{\"name\":\"out\",\"type\":\"TcpConnector\",\"settings\":{\"address\":"
      "\"127.0.0.1\",\"port\":9}}]}";
  static const char vless_mux[] =
      "{\"name\":\"vless-mux\",\"nodes\":["
      "{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"settings\":{},\"next\":"
      "\"ptc\"},"
      "{\"name\":\"ptc\",\"type\":\"PacketsToConnection\",\"settings\":{},"
      "\"next\":\"vless\"},"
      "{\"name\":\"vless\",\"type\":\"VlessClient\",\"settings\":{"
      "\"uuid\":\"00112233-4455-6677-8899-aabbccddeeff\",\"address\":\"example."
      "com\",\"port\":80,"
      "\"protocol\":\"tcp\",\"domain-strategy\":\"do-not-resolve-domains\"},"
      "\"next\":\"mux\"},"
      "{\"name\":\"mux\",\"type\":\"MuxClient\",\"settings\":{\"mode\":"
      "\"counter\",\"connection-capacity\":128},"
      "\"next\":\"tls\"},"
      "{\"name\":\"tls\",\"type\":\"TlsClient\",\"settings\":{\"sni\":"
      "\"localhost\",\"verify\":false},"
      "\"next\":\"out\"},"
      "{\"name\":\"out\",\"type\":\"TcpConnector\",\"settings\":{\"address\":"
      "\"127.0.0.1\",\"port\":9}}]}";
  static const char trojan_mux[] =
      "{\"name\":\"trojan-mux\",\"nodes\":["
      "{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"settings\":{},\"next\":"
      "\"ptc\"},"
      "{\"name\":\"ptc\",\"type\":\"PacketsToConnection\",\"settings\":{},"
      "\"next\":\"trojan\"},"
      "{\"name\":\"trojan\",\"type\":\"TrojanClient\",\"settings\":{"
      "\"password\":\"native-poc-placeholder\",\"address\":\"example.com\","
      "\"port\":80,"
      "\"protocol\":\"tcp\",\"domain-strategy\":\"do-not-resolve-domains\"},"
      "\"next\":\"mux\"},"
      "{\"name\":\"mux\",\"type\":\"MuxClient\",\"settings\":{\"mode\":"
      "\"counter\",\"connection-capacity\":128},"
      "\"next\":\"tls\"},"
      "{\"name\":\"tls\",\"type\":\"TlsClient\",\"settings\":{\"sni\":"
      "\"localhost\",\"verify\":false},"
      "\"next\":\"out\"},"
      "{\"name\":\"out\",\"type\":\"TcpConnector\",\"settings\":{\"address\":"
      "\"127.0.0.1\",\"port\":9}}]}";
  static const char wireguard[] =
      "{\"name\":\"wireguard\",\"nodes\":["
      "{\"name\":\"udp\",\"type\":\"UdpStatelessSocket\",\"settings\":{"
      "\"listen-address\":\"127.0.0.1\",\"listen-port\":51821},\"next\":\"wg\"}"
      ","
      "{\"name\":\"wg\",\"type\":\"WireGuardDevice\",\"settings\":{"
      "\"privatekey\":\"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\","
      "\"peers\":[{"
      "\"publickey\":\"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\","
      "\"allowedips\":\"0.0.0.0/0\","
      "\"endpoint\":\"127.0.0.1:51820\",\"persistentkeepalive\":15}]},\"next\":"
      "\"ne\"},"
      "{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"settings\":{}}]}";

  static const char raw_reality[] =
      "{\"name\":\"raw-reality\",\"nodes\":["
      "{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"settings\":{},\"next\":"
      "\"pts\"},"
      "{\"name\":\"pts\",\"type\":\"PacketsToStream\",\"settings\":{},\"next\":"
      "\"reality\"},"
      "{\"name\":\"reality\",\"type\":\"RealityClient\",\"settings\":{\"sni\":"
      "\"localhost\",\"verify\":false,\"password\":\"native-poc-placeholder\"},"
      "\"next\":\"out\"},"
      "{\"name\":\"out\",\"type\":\"TcpConnector\",\"settings\":{\"address\":"
      "\"127.0.0.1\",\"port\":9}}]}";
  static const char aead[] =
      "{\"name\":\"aead\",\"nodes\":["
      "{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"settings\":{},\"next\":"
      "\"ptc\"},"
      "{\"name\":\"ptc\",\"type\":\"PacketsToConnection\",\"settings\":{},"
      "\"next\":\"encryption\"},"
      "{\"name\":\"encryption\",\"type\":\"EncryptionClient\",\"settings\":{"
      "\"password\":\"native-poc-placeholder\"},\"next\":\"out\"},"
      "{\"name\":\"out\",\"type\":\"TcpConnector\",\"settings\":{\"address\":"
      "\"127.0.0.1\",\"port\":9}}]}";
  static const char quic[] =
      "{\"name\":\"quic\",\"nodes\":["
      "{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"settings\":{},\"next\":"
      "\"ptc\"},"
      "{\"name\":\"ptc\",\"type\":\"PacketsToConnection\",\"settings\":{},"
      "\"next\":\"vless\"},"
      "{\"name\":\"vless\",\"type\":\"VlessClient\",\"settings\":{\"uuid\":"
      "\"00112233-4455-6677-8899-aabbccddeeff\",\"address\":\"example.com\","
      "\"port\":80,\"protocol\":\"tcp\"},\"next\":\"quic\"},"
      "{\"name\":\"quic\",\"type\":\"QuicClient\",\"settings\":{\"sni\":"
      "\"localhost\",\"verify\":false,\"carrier-mode\":\"datagram\"},\"next\":"
      "\"out\"},"
      "{\"name\":\"out\",\"type\":\"UdpConnector\",\"settings\":{\"address\":"
      "\"127.0.0.1\",\"port\":9}}]}";

  static const char bgp4[] =
      "{\"name\":\"bgp4\",\"nodes\":["
      "{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"settings\":{},\"next\":"
      "\"ptc\"},"
      "{\"name\":\"ptc\",\"type\":\"PacketsToConnection\",\"settings\":{},"
      "\"next\":\"router\"},"
      "{\"name\":\"router\",\"type\":\"Router\",\"settings\":{"
      "\"resolve-domains\":false,\"rules\":[{\"destination-ip\":[\"10.0.0.0/"
      "8\"],"
      "\"target\":\"direct-local\"}]},\"next\":\"vless\"},"
      "{\"name\":\"direct-local\",\"type\":\"TcpUdpConnector\",\"settings\":{"
      "\"address\":\"dest_context->address\",\"port\":\"dest_context->port\","
      "\"domain-strategy\":\"prefer-ipv4\",\"nodelay\":true}},"
      "{\"name\":\"vless\",\"type\":\"VlessClient\",\"settings\":{\"uuid\":"
      "\"00112233-4455-6677-8899-aabbccddeeff\",\"address\":\"example.com\","
      "\"port\":80,\"protocol\":\"tcp\"},\"next\":\"bgp4\"},"
      "{\"name\":\"bgp4\",\"type\":\"Bgp4Client\",\"settings\":{},\"next\":"
      "\"out\"},"
      "{\"name\":\"out\",\"type\":\"TcpConnector\",\"settings\":{\"address\":"
      "\"127.0.0.1\",\"port\":9}}]}";
  static const char bgp4_kcp[] =
      "{\"name\":\"bgp4-kcp\",\"nodes\":["
      "{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"settings\":{},\"next\":"
      "\"ptc\"},"
      "{\"name\":\"ptc\",\"type\":\"PacketsToConnection\",\"settings\":{},"
      "\"next\":\"router\"},"
      "{\"name\":\"router\",\"type\":\"Router\",\"settings\":{"
      "\"resolve-domains\":false},\"next\":\"vless\"},"
      "{\"name\":\"vless\",\"type\":\"VlessClient\",\"settings\":{\"uuid\":"
      "\"00112233-4455-6677-8899-aabbccddeeff\",\"address\":\"example.com\","
      "\"port\":80,\"protocol\":\"tcp\"},\"next\":\"bgp4\"},"
      "{\"name\":\"bgp4\",\"type\":\"Bgp4Client\",\"settings\":{},\"next\":"
      "\"kcp\"},"
      "{\"name\":\"kcp\",\"type\":\"TcpOverUdpClient\",\"settings\":{},"
      "\"next\":"
      "\"out\"},"
      "{\"name\":\"out\",\"type\":\"UdpConnector\",\"settings\":{\"address\":"
      "\"127.0.0.1\",\"port\":9}}]}";

  checkChain("BGP4 Router VLESS TCP", bgp4);
  checkChain("BGP4 Router VLESS KCP", bgp4_kcp);
  checkChain("Raw IPv4 Reality", raw_reality);
  checkChain("AEAD", aead);
  checkChain("VLESS QUIC", quic);
  checkChain("VLESS TLS", vless);
  checkChain("Trojan TLS", trojan);
  checkChain("VLESS MUX TLS", vless_mux);
  checkChain("Trojan MUX TLS", trojan_mux);
  checkChain("WireGuard", wireguard);
  return 0;
}
