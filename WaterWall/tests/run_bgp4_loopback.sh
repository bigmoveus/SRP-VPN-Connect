#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${POC_PEER_BUILD_DIR:-${TMPDIR:-/tmp}/srp-bgp4-peer-lite}"
mkdir -p "$WORK"
if [ "${POC_SKIP_BUILD:-0}" != "1" ]; then
    cmake -S "$ROOT/upstream" -B "$WORK" -DBUILD_TESTING=OFF -DWW_ENABLE_IPO=OFF \
        -DWCRYPTO_BACKEND_OPENSSL=OFF -DINCLUDE_TLS_SERVER=OFF \
        -DINCLUDE_VMESS_SERVER=OFF -DINCLUDE_VMESS_CLIENT=OFF -Drouter_enable_quic_sniffing=OFF
    cmake --build "$WORK" --target Waterwall -j8
fi
PEER="$WORK/Release/Waterwall"
if [ ! -x "$PEER" ]; then
    PEER="$WORK/Waterwall"
fi
if [ ! -x "$PEER" ]; then
    echo "WaterWall peer binary was not built" >&2
    exit 1
fi

if [ "${POC_SKIP_BUILD:-0}" != "1" ]; then
    "$ROOT/build.sh" host
fi
cd "$ROOT"
PEER_PID=""
DNS_PID=""
TMPDIR_TEST=""
cleanup() {
    status=$?
    if [ -n "$PEER_PID" ]; then
        kill "$PEER_PID" 2>/dev/null || true
        wait "$PEER_PID" 2>/dev/null || true
    fi
    if [ -n "$DNS_PID" ]; then
        kill "$DNS_PID" 2>/dev/null || true
        wait "$DNS_PID" 2>/dev/null || true
    fi
    if [ "$status" -ne 0 ] && [ -n "$TMPDIR_TEST" ]; then
        cat "$TMPDIR_TEST/peer.log" "$TMPDIR_TEST/dns.log" >&2 || true
    fi
    if [ -n "$TMPDIR_TEST" ] && [ "${POC_KEEP_TMP:-0}" != "1" ]; then
        rm -rf "$TMPDIR_TEST"
    fi
    exit "$status"
}
trap cleanup EXIT

if [ -n "${POC_HOST_BUILD_DIR:-}" ]; then
    ctest_args=(--test-dir "$POC_HOST_BUILD_DIR" -C "${POC_HOST_CONFIGURATION:-Release}")
else
    ctest_args=(--preset host)
fi

run_case() {
    local transport="$1"
    local buffer_mode="$2"
    read -r http_port peer_port <<< "$(python3 - <<'PY'
import socket
sockets = []
for _ in range(2):
    item = socket.socket()
    item.bind(('127.0.0.1', 0))
    sockets.append(item)
    print(item.getsockname()[1], end=' ')
for item in sockets:
    item.close()
PY
)"
    TMPDIR_TEST="$(mktemp -d "${TMPDIR:-/tmp}/srp-bgp4-test.XXXXXX")"
    local dns_ip="${POC_DNS_IP:-$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)}"
    if [ -z "$dns_ip" ]; then
        echo "Set POC_DNS_IP to an IPv4 address assigned to this Mac" >&2
        return 1
    fi
    local listener="TcpListener"
    local listener_next="bgp4"
    local carrier=""
    local kcp_settings='{"kcp-recv-window":512,"kcp-send-buffer-limit":512}'
    if [ -n "${POC_KCP_SETTINGS:-}" ]; then
        kcp_settings="$POC_KCP_SETTINGS"
    fi
    if [ "$transport" = "kcp" ]; then
        listener="UdpListener"
        listener_next="kcp"
        carrier="{\"name\":\"kcp\",\"type\":\"TcpOverUdpServer\",\"settings\":$kcp_settings,\"next\":\"bgp4\"},"
    fi
    cat > "$TMPDIR_TEST/core.json" <<EOF
{"misc":{"workers":1,"ram-profile":"minimal"},"configs":["$TMPDIR_TEST/nodes.json"]}
EOF
    cat > "$TMPDIR_TEST/nodes.json" <<EOF
{"name":"bgp4-peer","nodes":[
  {"name":"listener","type":"$listener","settings":{"address":"127.0.0.1","port":$peer_port},"next":"$listener_next"},
  $carrier
  {"name":"bgp4","type":"Bgp4Server","settings":{},"next":"vless"},
  {"name":"vless","type":"VlessServer","settings":{"uuid":"00112233-4455-6677-8899-aabbccddeeff"},"next":"out"},
  {"name":"out","type":"TcpUdpConnector","settings":{"address":"dest_context->address","port":"dest_context->port","nodelay":true}}
]}
EOF
    "$PEER" --config:"$TMPDIR_TEST/core.json" > "$TMPDIR_TEST/peer.log" 2>&1 &
    PEER_PID=$!
    python3 -u - "$dns_ip" > "$TMPDIR_TEST/dns.log" 2>&1 <<'PY' &
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((sys.argv[1], 0))
print(sock.getsockname()[1], flush=True)
data, peer = sock.recvfrom(65535)
if len(data) < 12:
    raise RuntimeError('short DNS request')
response = bytearray(data)
response[2] |= 0x80
response[3] |= 0x80
sock.sendto(response, peer)
PY
    DNS_PID=$!
    for _ in $(seq 1 100); do
        [ -s "$TMPDIR_TEST/dns.log" ] && break
        sleep 0.05
    done
    read -r dns_port < "$TMPDIR_TEST/dns.log"
    case "$dns_port" in
        ''|*[!0-9]*) echo "UDP responder did not start" >&2; return 1 ;;
    esac
    if [ "$transport" = "tcp" ]; then
        python3 - "$peer_port" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
for _ in range(100):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=0.1):
            break
    except OSError:
        time.sleep(0.1)
else:
    raise SystemExit('BGP4 peer did not start listening')
PY
    else
        sleep 1
    fi
    if [ "$transport" = "kcp" ]; then
        export POC_BGP4_KCP=1
    else
        unset POC_BGP4_KCP
    fi
    if [ "$buffer_mode" = "no-splice" ]; then
        export POC_MINIMAL=1
    else
        unset POC_MINIMAL
    fi
    POC_BGP4=1 POC_BGP4_PORT="$peer_port" POC_HTTP_PORT="$http_port" \
        ctest "${ctest_args[@]}" --output-on-failure -R '^srp_waterwall_host_poc$'
    POC_BGP4=1 POC_BGP4_PORT="$peer_port" POC_DNS_PORT="$dns_port" POC_DNS_IP="$dns_ip" \
        ctest "${ctest_args[@]}" --output-on-failure -R '^srp_waterwall_vless_mux_udp_poc$'
    kill "$PEER_PID" "$DNS_PID" 2>/dev/null || true
    wait "$PEER_PID" 2>/dev/null || true
    wait "$DNS_PID" 2>/dev/null || true
    PEER_PID=""
    DNS_PID=""
    rm -rf "$TMPDIR_TEST"
    TMPDIR_TEST=""
}

for transport in tcp kcp; do
    for buffer_mode in default no-splice; do
        if [ -n "${POC_CASE:-}" ] && [ "$POC_CASE" != "$transport-$buffer_mode" ]; then
            continue
        fi
        run_case "$transport" "$buffer_mode"
    done
done

echo "BGP4 loopback passed: Router + VLESS, TCP and KCP, splice and no-splice"
