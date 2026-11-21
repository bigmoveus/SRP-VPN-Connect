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
      "\"protocol\":\"tcp\"},"
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
      "\"protocol\":\"tcp\"},"
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
      "\"protocol\":\"tcp\"},"
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
      "\"protocol\":\"tcp\"},"
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
      "{\"name\":\"wireguard\",\"nodes\":[{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"s"
      "ettings\":{},\"next\":\"wg\"},{\"name\":\"wg\",\"type\":\"WireGuardClient\",\"next"
      "\":\"udp\",\"settings\":{\"privatekey\":\"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ"
      "EBAQEBAQE=\",\"peers\":[{\"publickey\":\"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA"
      "QEBAQEBAQE=\",\"allowedips\":\"0.0.0.0/0\",\"endpoint\":\"127.0.0.1:51820\",\""
      "persistentkeepalive\":15}]}},{\"name\":\"udp\",\"type\":\"UdpConnector\",\"set"
      "tings\":{\"address\":\"dest_context->address\",\"port\":\"dest_context->port"
      "\"}}]}";

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
      "{\"name\":\"quic\",\"nodes\":[{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"settin"
      "gs\":{},\"next\":\"ptc\"},{\"name\":\"ptc\",\"type\":\"PacketsToConnection\",\"set"
      "tings\":{},\"next\":\"vless\"},{\"name\":\"vless\",\"type\":\"VlessClient\",\"sett"
      "ings\":{\"uuid\":\"00112233-4455-6677-8899-aabbccddeeff\",\"address\":\"exam"
      "ple.com\",\"port\":80,\"protocol\":\"tcp\"},\"next\":\"quic\"},{\"name\":\"quic\",\""
      "type\":\"QuicClient\",\"settings\":{\"sni\":\"localhost\",\"verify\":false},\"ne"
      "xt\":\"out\"},{\"name\":\"out\",\"type\":\"UdpConnector\",\"settings\":{\"address\""
      ":\"127.0.0.1\",\"port\":9}}]}";
  static const char quic_tcp[] =
      "{\"name\":\"quic-tcp\",\"nodes\":[{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"se"
      "ttings\":{},\"next\":\"ptc\"},{\"name\":\"ptc\",\"type\":\"PacketsToConnection\","
      "\"settings\":{},\"next\":\"vless\"},{\"name\":\"vless\",\"type\":\"VlessClient\",\""
      "settings\":{\"uuid\":\"00112233-4455-6677-8899-aabbccddeeff\",\"address\":\""
      "example.com\",\"port\":80,\"protocol\":\"tcp\"},\"next\":\"quic\"},{\"name\":\"qui"
      "c\",\"type\":\"QuicClient\",\"settings\":{\"sni\":\"localhost\",\"verify\":false}"
      ",\"next\":\"framing\"},{\"name\":\"framing\",\"type\":\"UdpOverTcpClient\",\"sett"
      "ings\":{},\"next\":\"out\"},{\"name\":\"out\",\"type\":\"TcpConnector\",\"settings"
      "\":{\"address\":\"127.0.0.1\",\"port\":9}}]}";
  static const char striped_rtmp_reality[] =
      "{\"name\":\"striped-rtmp-reality\",\"nodes\":[{\"name\":\"ne\",\"type\":\"NEPacke"
      "tDevice\",\"settings\":{},\"next\":\"ptc\"},{\"name\":\"ptc\",\"type\":\"PacketsTo"
      "Connection\",\"settings\":{},\"next\":\"trojan\"},{\"name\":\"trojan\",\"type\":\""
      "TrojanClient\",\"next\":\"mux\",\"settings\":{\"password\":\"native-poc-placeh"
      "older\",\"address\":\"dest_context->address\",\"port\":\"dest_context->port\""
      ",\"protocol\":\"dest_context->protocol\"}},{\"name\":\"mux\",\"type\":\"MuxClie"
      "nt\",\"next\":\"half-duplex\",\"settings\":{\"mode\":\"fixed-connections-count"
      "\",\"per-worker-connections-count\":1}},{\"name\":\"half-duplex\",\"type\":\"H"
      "alfDuplexClient\",\"settings\":{\"upload\":\"up\",\"download\":\"down\"}},{\"nam"
      "e\":\"up\",\"type\":\"ConnectionStripeClient\",\"settings\":{\"connections\":8}"
      ",\"next\":\"obfuscator\"},{\"name\":\"obfuscator\",\"type\":\"ObfuscatorClient\""
      ",\"settings\":{\"method\":\"xor\",\"xor_key\":90},\"next\":\"rtmp\"},{\"name\":\"rt"
      "mp\",\"type\":\"RtmpClient\",\"settings\":{\"tc-url\":\"rtmp://127.0.0.1:1935/"
      "waterwall\"},\"next\":\"rtmp-out\"},{\"name\":\"rtmp-out\",\"type\":\"TcpConnect"
      "or\",\"settings\":{\"address\":\"127.0.0.1\",\"port\":9}},{\"name\":\"down\",\"typ"
      "e\":\"RealityClient\",\"settings\":{\"sni\":\"localhost\",\"verify\":false,\"pas"
      "sword\":\"native-poc-placeholder\"},\"next\":\"reality-out\"},{\"name\":\"real"
      "ity-out\",\"type\":\"TcpConnector\",\"settings\":{\"address\":\"127.0.0.1\",\"po"
      "rt\":9}}]}";
  static const char enet[] =
      "{\"name\":\"enet\",\"nodes\":[{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"settin"
      "gs\":{},\"next\":\"ptc\"},{\"name\":\"ptc\",\"type\":\"PacketsToConnection\",\"set"
      "tings\":{},\"next\":\"vless\"},{\"name\":\"vless\",\"type\":\"VlessClient\",\"sett"
      "ings\":{\"uuid\":\"00112233-4455-6677-8899-aabbccddeeff\",\"address\":\"exam"
      "ple.com\",\"port\":80,\"protocol\":\"tcp\"},\"next\":\"enet\"},{\"name\":\"enet\",\""
      "type\":\"EnetClient\",\"settings\":{\"send-mtu\":1400},\"next\":\"out\"},{\"name"
      "\":\"out\",\"type\":\"UdpConnector\",\"settings\":{\"address\":\"127.0.0.1\",\"por"
      "t\":9}}]}";
  static const char gns[] =
      "{\"name\":\"gns\",\"nodes\":[{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"setting"
      "s\":{},\"next\":\"ptc\"},{\"name\":\"ptc\",\"type\":\"PacketsToConnection\",\"sett"
      "ings\":{},\"next\":\"vless\"},{\"name\":\"vless\",\"type\":\"VlessClient\",\"setti"
      "ngs\":{\"uuid\":\"00112233-4455-6677-8899-aabbccddeeff\",\"address\":\"examp"
      "le.com\",\"port\":80,\"protocol\":\"tcp\"},\"next\":\"gns\"},{\"name\":\"gns\",\"typ"
      "e\":\"GnsClient\",\"settings\":{\"send-mtu\":1400,\"send-rate\":4194304},\"nex"
      "t\":\"out\"},{\"name\":\"out\",\"type\":\"UdpConnector\",\"settings\":{\"address\":"
      "\"127.0.0.1\",\"port\":9}}]}";
  static const char helpers[] =
      "{\"name\":\"helpers\",\"nodes\":[{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"set"
      "tings\":{},\"next\":\"ptc\"},{\"name\":\"ptc\",\"type\":\"PacketsToConnection\",\""
      "settings\":{},\"next\":\"router\"},{\"name\":\"router\",\"type\":\"Router\",\"sett"
      "ings\":{\"rules\":[{\"destination-ip\":[\"192.0.2.0/24\"],\"target\":\"drop\"}]"
      "},\"next\":\"speed\"},{\"name\":\"drop\",\"type\":\"BlackHole\",\"settings\":{\"mod"
      "e\":\"passive\"}},{\"name\":\"speed\",\"type\":\"SpeedLimit\",\"settings\":{\"kilo"
      "-bytes-per-sec\":256,\"limit-mode\":\"per-line\",\"work-mode\":\"pause\"},\"ne"
      "xt\":\"log\"},{\"name\":\"log\",\"type\":\"LoggerTunnel\",\"settings\":{\"mode\":\"l"
      "og\",\"level\":\"info\"},\"next\":\"disturber\"},{\"name\":\"disturber\",\"type\":\""
      "Disturber\",\"settings\":{\"disturb-upstream\":true,\"disturb-downstream\":"
      "false,\"chance_payload_delay\":1,\"delay_min_ms\":1,\"delay_max_ms\":2},\"n"
      "ext\":\"vless\"},{\"name\":\"vless\",\"type\":\"VlessClient\",\"settings\":{\"uuid"
      "\":\"00112233-4455-6677-8899-aabbccddeeff\",\"address\":\"example.com\",\"po"
      "rt\":80,\"protocol\":\"tcp\"},\"next\":\"keepalive\"},{\"name\":\"keepalive\",\"ty"
      "pe\":\"KeepAliveClient\",\"settings\":{\"ping-interval\":30000,\"sensitive-m"
      "ode\":false,\"tolerance-ms\":90000},\"next\":\"header\"},{\"name\":\"header\",\""
      "type\":\"HeaderClient\",\"settings\":{\"data\":\"src_context->port\"},\"next\":"
      "\"fisher\"},{\"name\":\"fisher\",\"type\":\"ConnectionFisherClient\",\"settings"
      "\":{\"simultaneous-tries-perline\":3},\"next\":\"out\"},{\"name\":\"out\",\"type"
      "\":\"TcpConnector\",\"settings\":{\"address\":\"127.0.0.1\",\"port\":9}}]}";
  static const char kcp_junk[] =
      "{\"name\":\"kcp-junk\",\"nodes\":[{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"se"
      "ttings\":{},\"next\":\"ptc\"},{\"name\":\"ptc\",\"type\":\"PacketsToConnection\","
      "\"settings\":{},\"next\":\"vless\"},{\"name\":\"vless\",\"type\":\"VlessClient\",\""
      "settings\":{\"uuid\":\"00112233-4455-6677-8899-aabbccddeeff\",\"address\":\""
      "example.com\",\"port\":80,\"protocol\":\"tcp\"},\"next\":\"kcp\"},{\"name\":\"kcp\""
      ",\"type\":\"KcpClient\",\"settings\":{},\"next\":\"junk\"},{\"name\":\"junk\",\"typ"
      "e\":\"JunkDatagramSender\",\"settings\":{\"packet-count-perline-min\":2,\"pa"
      "cket-count-perline-max\":5,\"resend-again-times\":1,\"selected-protocols"
      "\":[\"dns\",\"ntp\"],\"keep-sending-max-ms\":1500},\"next\":\"out\"},{\"name\":\"o"
      "ut\",\"type\":\"UdpConnector\",\"settings\":{\"address\":\"127.0.0.1\",\"port\":9"
      "}}]}";
  static const char connections_wireguard[] =
      "{\"name\":\"connections-wireguard\",\"nodes\":[{\"name\":\"ne\",\"type\":\"NEPack"
      "etDevice\",\"settings\":{},\"next\":\"ptc\"},{\"name\":\"ptc\",\"type\":\"PacketsT"
      "oConnection\",\"settings\":{},\"next\":\"ctp\"},{\"name\":\"ctp\",\"type\":\"Conne"
      "ctionToPackets\",\"settings\":{\"source-ipv4\":\"10.90.0.1\",\"mtu\":1420},\"n"
      "ext\":\"wg\"},{\"name\":\"wg\",\"type\":\"WireGuardClient\",\"next\":\"udp\",\"setti"
      "ngs\":{\"privatekey\":\"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\",\"p"
      "eers\":[{\"publickey\":\"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\",\""
      "allowedips\":\"0.0.0.0/0\",\"endpoint\":\"127.0.0.1:51820\",\"persistentkeep"
      "alive\":15}]}},{\"name\":\"udp\",\"type\":\"UdpConnector\",\"settings\":{\"addre"
      "ss\":\"dest_context->address\",\"port\":\"dest_context->port\"}}]}";

  static const char bgp4[] =
      "{\"name\":\"bgp4\",\"nodes\":["
      "{\"name\":\"ne\",\"type\":\"NEPacketDevice\",\"settings\":{},\"next\":"
      "\"ptc\"},"
      "{\"name\":\"ptc\",\"type\":\"PacketsToConnection\",\"settings\":{},"
      "\"next\":\"router\"},"
      "{\"name\":\"router\",\"type\":\"Router\",\"settings\":{"
      "\"rules\":[{\"destination-ip\":[\"10.0.0.0/"
      "8\"],"
      "\"target\":\"direct-local\"}]},\"next\":\"vless\"},"
      "{\"name\":\"direct-local\",\"type\":\"TcpUdpConnector\",\"settings\":{"
      "\"address\":\"dest_context->address\",\"port\":\"dest_context->port\","
      "\"dns-behaviour\":{\"resolve\":true,\"strategy\":\"prefer-ipv4\"},\"nodelay\":true}},"
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
      "},\"next\":\"vless\"},"
      "{\"name\":\"vless\",\"type\":\"VlessClient\",\"settings\":{\"uuid\":"
      "\"00112233-4455-6677-8899-aabbccddeeff\",\"address\":\"example.com\","
      "\"port\":80,\"protocol\":\"tcp\"},\"next\":\"bgp4\"},"
      "{\"name\":\"bgp4\",\"type\":\"Bgp4Client\",\"settings\":{},\"next\":"
      "\"kcp\"},"
      "{\"name\":\"kcp\",\"type\":\"KcpClient\",\"settings\":{},"
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
  // WaterWall 1.6: QUIC over TCP, and the nodes that came with it
  checkChain("VLESS QUIC over TCP", quic_tcp);
  checkChain("Striped RTMP upload, Reality download", striped_rtmp_reality);
  checkChain("VLESS ENet", enet);
  checkChain("VLESS GNS", gns);
  checkChain("Helper nodes", helpers);
  checkChain("VLESS KCP with junk datagrams", kcp_junk);
  checkChain("Connections into WireGuard", connections_wireguard);
  return 0;
}
