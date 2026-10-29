#!/usr/bin/env python3
import argparse
import copy
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
UUID = "00112233-4455-6677-8899-aabbccddeeff"
OUTER_SECRET = "matrix-only-placeholder"
GEO_DATABASE = ROOT / "SRP-VPN-Connect/GeoIP/GeoLite2-Country.mmdb"

CASES = [
    ("vless-none", "vless", "none", False, "off", False, "tcp", "datagram", "connections"),
    ("vless-tls", "vless", "tls", False, "off", False, "tcp", "datagram", "connections"),
    ("vless-reality", "vless", "reality", False, "off", False, "tcp", "datagram", "connections"),
    ("vless-aead", "vless", "aead", False, "off", False, "tcp", "datagram", "connections"),
    ("vless-quic", "vless", "quic", False, "off", False, "tcp", "datagram", "connections"),
    ("vless-quic-stream", "vless", "quic", False, "off", False, "tcp", "stream", "connections"),
    ("vless-bgp4-quic-stream", "vless", "quic", False, "off", False, "tcp", "stream", "connections"),
    ("vless-kcp", "vless", "none", False, "off", False, "kcp", "datagram", "connections"),
    ("vless-bgp4", "vless", "bgp4", False, "off", False, "tcp", "datagram", "connections"),
    ("vless-bgp4-kcp", "vless", "bgp4", False, "off", False, "kcp", "datagram", "connections"),
    ("vless-bgp4-tls", "vless", "tls", False, "off", False, "tcp", "datagram", "connections"),
    ("vless-bgp4-tls-kcp", "vless", "tls", False, "off", False, "kcp", "datagram", "connections"),
    ("vless-bgp4-reality-kcp", "vless", "reality", False, "off", False, "kcp", "datagram", "connections"),
    ("vless-mux-tls", "vless", "tls", True, "off", False, "tcp", "datagram", "connections"),
    ("vless-mux-bgp4-tls-kcp", "vless", "tls", True, "off", False, "kcp", "datagram", "connections"),
    ("vless-http1-tls", "vless", "tls", False, "http", False, "tcp", "datagram", "connections", 1),
    ("vless-http2-tls", "vless", "tls", False, "http", False, "tcp", "datagram", "connections", 2),
    ("vless-websocket-tls", "vless", "tls", False, "websocket", False, "tcp", "datagram", "connections"),
    ("vless-xor-bgp4-tls-kcp", "vless", "tls", False, "off", True, "kcp", "datagram", "connections"),
    ("trojan-tls", "trojan", "tls", False, "off", False, "tcp", "datagram", "connections"),
    ("trojan-reality", "trojan", "reality", False, "off", False, "tcp", "datagram", "connections"),
    ("trojan-mux-tls", "trojan", "tls", True, "off", False, "tcp", "datagram", "connections"),
    ("trojan-bgp4-tls-kcp", "trojan", "tls", False, "off", False, "kcp", "datagram", "connections"),
    ("vmess-tls", "vmess", "tls", False, "off", False, "tcp", "datagram", "connections"),
    ("vmess-reality", "vmess", "reality", False, "off", False, "tcp", "datagram", "connections"),
    ("vmess-aead", "vmess", "aead", False, "off", False, "tcp", "datagram", "connections"),
    ("vmess-quic", "vmess", "quic", False, "off", False, "tcp", "datagram", "connections"),
    ("vmess-bgp4-tls-kcp", "vmess", "tls", False, "off", False, "kcp", "datagram", "connections"),
    ("socks5-none", "socks5", "none", False, "off", False, "tcp", "datagram", "connections"),
    ("http-connect-tls", "http-proxy", "tls", False, "off", False, "tcp", "datagram", "connections"),
    ("raw-tls", "", "tls", False, "off", False, "tcp", "datagram", "raw-ipv4"),
    ("raw-reality", "", "reality", False, "off", False, "tcp", "datagram", "raw-ipv4"),
    ("raw-aead", "", "aead", False, "off", False, "tcp", "datagram", "raw-ipv4"),
    ("geoip-direct-iran", "vless", "tls", False, "off", False, "tcp", "datagram", "connections"),
    ("geoip-default-proxy", "vless", "tls", False, "off", False, "tcp", "datagram", "connections"),
    ("geoip-multi-countries", "vless", "tls", False, "off", False, "tcp", "datagram", "connections"),
]


def configuration(spec, port):
    name, app, outer, mux, http, obfuscator, carrier, quic_carrier, input_mode = spec[:9]
    version = spec[9] if len(spec) > 9 else 1
    config = {
        "version": 3,
        "mode": "chain",
        "input": input_mode,
        "application": app,
        "mux": mux,
        "outer": outer,
        "http": http,
        "http-version": version,
        "obfuscator": obfuscator,
        "carrier": carrier,
        "quic-carrier": quic_carrier,
        "node-options": {},
    }
    if os.environ.get("SRP_MATRIX_DEBUG") == "1":
        if app in ("vless", "vmess"):
            config["node-options"]["application"] = {"verbose": True}
        if outer == "quic":
            config["node-options"]["outer"] = {"verbose": True}
    entry = {
        "configuration": config,
        "server": "127.0.0.1",
        "port": port,
        "sni": "localhost",
        "verifyTLS": False,
        "options": {"ww_fake_dns": True},
    }
    if app in ("vless", "vmess", "trojan"):
        entry["secret"] = UUID
    if outer in ("reality", "aead"):
        entry["outerSecret"] = OUTER_SECRET
    if name.startswith("geoip-"):
        config["geoip"] = {"countries": ["IR", "US"]} if name == "geoip-multi-countries" else {"iran-direct": True}
        entry["options"]["ww_geoip_db_path"] = str(GEO_DATABASE)
    if "bgp4" in name and outer != "bgp4":
        config["bgp4"] = True
    return entry


def main_chain(nodes):
    by_name = {node["name"]: node for node in nodes}
    result = []
    name = by_name["ne"]["next"]
    while name:
        node = by_name[name]
        result.append(node)
        name = node.get("next")
    return result


def peer_nodes(client_root, port, cert, key, cover_port):
    result = []
    for node in main_chain(client_root["nodes"]):
        kind = node["type"]
        if kind in ("NEPacketDevice", "PacketsToConnection", "Router"):
            continue
        settings = {}
        server_type = None
        if kind == "VlessClient":
            server_type = "VlessServer"
            settings = {"uuid": node["settings"]["uuid"], "verbose": True}
        elif kind == "VmessClient":
            server_type = "VmessServer"
            settings = {"uuid": node["settings"]["uuid"], "udp": True}
        elif kind == "TrojanClient":
            server_type = "TrojanServer"
            settings = {"password": node["settings"]["password"]}
        elif kind == "Socks5Client":
            server_type = "Socks5Server"
            settings = {"no-auth": True, "connect": True, "udp": True, "ipv4": "127.0.0.1"}
        elif kind == "HttpProxyClient":
            server_type = "HttpProxyServer"
            settings = {"no-auth": True}
        elif kind == "MuxClient":
            server_type = "MuxServer"
        elif kind == "HttpClient":
            server_type = "HttpServer"
            for field in ("host", "path", "method", "http-version", "websocket", "upgrade",
                          "upgrade-protocol", "content-type", "http1-mode", "split",
                          "websocket-origin", "websocket-subprotocol", "headers"):
                if field in node["settings"]:
                    settings[field] = node["settings"][field]
        elif kind == "ObfuscatorClient":
            server_type = "ObfuscatorServer"
            settings = copy.deepcopy(node["settings"])
        elif kind == "TlsClient":
            server_type = "TlsServer"
            settings = {"cert-file": str(cert), "key-file": str(key), "verbose": True}
            if "alpns" in node["settings"]:
                settings["select-alpns"] = node["settings"]["alpns"]
        elif kind == "RealityClient":
            server_type = "RealityServer"
            for field in ("password", "algorithm", "salt", "kdf-iterations"):
                if field in node["settings"]:
                    settings[field] = node["settings"][field]
            settings["destination"] = "cover"
        elif kind == "EncryptionClient":
            server_type = "EncryptionServer"
            for field in ("password", "algorithm", "salt", "kdf-iterations", "max-frame-size"):
                if field in node["settings"]:
                    settings[field] = node["settings"][field]
        elif kind == "QuicClient":
            server_type = "QuicServer"
            for field in ("protocol", "carrier-mode", "handshake-timeout-ms", "idle-timeout-ms",
                          "max-packet-size", "max-buffered-bytes", "max-buffered-buffers", "receive-window-bytes", "verbose"):
                if field in node["settings"]:
                    settings[field] = node["settings"][field]
            settings.update({"cert-file": str(cert), "key-file": str(key)})
        elif kind == "Bgp4Client":
            server_type = "Bgp4Server"
            settings = copy.deepcopy(node["settings"])
        elif kind == "TcpOverUdpClient":
            server_type = "TcpOverUdpServer"
            settings = copy.deepcopy(node["settings"])
        elif kind in ("TcpConnector", "UdpConnector", "TcpUdpConnector"):
            continue
        elif kind == "PacketsToStream":
            continue
        else:
            raise ValueError(f"No test peer mapping for {kind}")
        result.append({"name": node["name"], "type": server_type, "settings": settings})
    result.reverse()
    if any(node["type"] == "PacketsToStream" for node in client_root["nodes"]):
        result.append({"name": "stp", "type": "StreamToPackets", "settings": {"packet-validation-level": "hard"}})
        result.append({"name": "ptc", "type": "PacketsToConnection", "settings": {}})
    result.append({"name": "out", "type": "TcpUdpConnector", "settings": {
        "address": "dest_context->address", "port": "dest_context->port",
        "domain-strategy": "prefer-ipv4", "nodelay": True}})
    connector = client_root["nodes"][-1]
    stream_outer = any(node["type"] in ("TlsClient", "RealityClient", "EncryptionClient")
                       for node in client_root["nodes"])
    kcp_carrier = any(node["type"] == "TcpOverUdpClient" for node in client_root["nodes"])
    listener_type = "UdpListener" if kcp_carrier else "TcpListener" if stream_outer else {
        "TcpConnector": "TcpListener", "UdpConnector": "UdpListener",
        "TcpUdpConnector": "TcpUdpListener"}[connector["type"]]
    listener = {"name": "listener", "type": listener_type,
                "settings": {"address": "127.0.0.1", "port": port}}
    result.insert(0, listener)
    for index, node in enumerate(result):
        if index + 1 < len(result):
            node["next"] = result[index + 1]["name"]
    if any(node["type"] == "RealityClient" for node in client_root["nodes"]):
        result.append({"name": "cover", "type": "TcpConnector",
                       "settings": {"address": "127.0.0.1", "port": cover_port, "nodelay": True}})
    return result


def write_json(path, value):
    if "configs" in value and os.environ.get("SRP_MATRIX_DEBUG") == "1":
        value = dict(value)
        value["log"] = {
            "core": {"loglevel": "DEBUG", "console": True},
            "network": {"loglevel": "DEBUG", "console": True},
        }
    path.write_text(json.dumps(value, indent=2) + "\n")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run_logged(command, log, env=None, timeout=60):
    with log.open("w") as output:
        return subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, env=env, timeout=timeout).returncode


def local_ipv4():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("192.0.2.1", 9))
        return sock.getsockname()[0]


def start_udp_responder(port, address=None, expected=None):
    address = address or os.environ.get("SRP_MATRIX_DNS_IP") or local_ipv4()
    expected = expected if expected is not None else int(os.environ.get("SRP_MATRIX_UDP_REPEAT", "1"))
    if not 1 <= expected <= 36000:
        raise ValueError("SRP_MATRIX_UDP_REPEAT must be between 1 and 36000")
    ready = threading.Event()
    failure = []
    bound_port = []
    def serve():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind((address, port))
                bound_port.append(sock.getsockname()[1])
                ready.set()
                for _ in range(expected):
                    data, peer = sock.recvfrom(65535)
                    if len(data) < 12:
                        raise ValueError("Short DNS request")
                    response = bytearray(data)
                    response[2] |= 0x80
                    response[3] |= 0x80
                    sock.sendto(response, peer)
        except Exception as error:
            failure.append(str(error))
            ready.set()
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    ready.wait(3)
    if failure:
        raise RuntimeError(failure[0])
    if not bound_port:
        raise RuntimeError("UDP responder startup timed out")
    return thread, failure, address, bound_port[0]


def stop_peer(process, timeout=10):
    if process is None:
        return 0
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    return process.returncode


def stop_peer_status(process):
    code = stop_peer(process)
    return {"passed": code in (0, -15, 130), "returncode": code}


def tail(path, count=40):
    if not path.exists():
        return ""
    lines = path.read_text(errors="replace").splitlines()
    return "\n".join(lines[-count:])


class Matrix:
    def __init__(self, args):
        self.args = args
        self.work = Path(tempfile.mkdtemp(prefix="srp-waterwall-matrix-"))
        self.peer_build = Path(os.environ.get("SRP_MATRIX_PEER_BUILD_DIR",
                                               Path(os.environ.get("TMPDIR", "/tmp")) / "srp-waterwall-matrix-peer"))
        self.peer = self.peer_build / "Waterwall"
        self.cert = self.work / "test-cert.pem"
        self.key = self.work / "test-key.pem"
        self.host_poc = ROOT / "WaterWall/build/host/Release/srp_waterwall_host_poc"
        self.udp_poc = ROOT / "WaterWall/build/host/Release/srp_waterwall_vless_mux_udp_poc"
        self.results = []

    def build_peer(self):
        if not self.args.build:
            if not self.peer.is_file():
                raise RuntimeError(f"Missing peer {self.peer}; use --build")
            return
        self.peer_build.mkdir(parents=True, exist_ok=True)
        configure = ["cmake", "-S", str(ROOT / "WaterWall/upstream"), "-B", str(self.peer_build),
                     "-DBUILD_TESTING=OFF", "-DWW_ENABLE_IPO=OFF", "-DINCLUDE_TLS_SERVER=ON",
                     "-DINCLUDE_VMESS_SERVER=ON", "-DINCLUDE_VMESS_CLIENT=ON",
                     "-DOPENSSL_CONFIGURE_OPTIONS=no-asm", "-DWCRYPTO_BACKEND_OPENSSL=OFF",
                     "-Drouter_enable_quic_sniffing=OFF", "-Drouter_enable_http2_sniffing=OFF"]
        if run_logged(configure, self.work / "peer-configure.log", timeout=600) != 0:
            raise RuntimeError(tail(self.work / "peer-configure.log"))
        if run_logged(["cmake", "--build", str(self.peer_build), "--target", "Waterwall", "-j8"],
                      self.work / "peer-build.log", timeout=600) != 0:
            raise RuntimeError(tail(self.work / "peer-build.log"))

    def generate_clients(self, selected):
        inputs = self.work / "builder-input.json"
        output = self.work / "builder-output.json"
        write_json(inputs, [configuration(spec, free_port()) for spec in selected])
        env = os.environ.copy()
        env["TEST_RUNNER_SRP_MATRIX_INPUT"] = str(inputs)
        env["TEST_RUNNER_SRP_MATRIX_OUTPUT"] = str(output)
        command = ["xcodebuild", "test", "-workspace", str(ROOT / "SRP-VPN-Connect.xcworkspace"),
                   "-scheme", "SRP-VPN-ConnectTestsMac", "-destination", "platform=macOS",
                   "-only-testing:SRP-VPN-ConnectTestsMac/SROptionsTests/testWaterWallMatrixGenerationForLocalTesting"]
        if run_logged(command, self.work / "builder.log", env=env, timeout=240) != 0:
            raise RuntimeError(tail(self.work / "builder.log"))
        generated = json.loads(output.read_text())
        clients = {}
        for spec, root in zip(selected, generated):
            path = self.work / f"{spec[0]}-client.json"
            write_json(path, root)
            clients[spec[0]] = path
        return clients

    def run_case(self, spec, client_path):
        name = spec[0]
        port = json.loads(client_path.read_text())["nodes"][-1]["settings"]["port"]
        cover_port = free_port()
        main_nodes = self.work / f"{name}-peer.json"
        cover_nodes = self.work / f"{name}-cover.json"
        core = self.work / f"{name}-core.json"
        root = json.loads(client_path.read_text())
        nodes = peer_nodes(root, port, self.cert, self.key, cover_port)
        write_json(main_nodes, {"name": f"{name}-peer", "nodes": nodes})
        configs = [str(main_nodes)]
        if any(node["type"] == "RealityClient" for node in root["nodes"]):
            write_json(cover_nodes, {"name": "cover-peer", "nodes": [
                {"name": "listener", "type": "TcpListener",
                 "settings": {"address": "127.0.0.1", "port": cover_port}, "next": "tls"},
                {"name": "tls", "type": "TlsServer",
                 "settings": {"cert-file": str(self.cert), "key-file": str(self.key)}, "next": "blackhole"},
                {"name": "blackhole", "type": "BlackHole", "settings": {"mode": "passive"}}]})
            configs.append(str(cover_nodes))
        write_json(core, {"misc": {"workers": 1, "ram-profile": "minimal", "splice": False,
                                    "try-enabling-bbr": False, "tcp-tune": False}, "configs": configs})
        peer_log = self.work / f"{name}-peer.log"
        process = None
        result = {"name": name, "tcp": {}, "udp": {}, "teardown": {}}
        try:
            with peer_log.open("w") as output:
                process = subprocess.Popen([str(self.peer), f"--config:{core}"], stdout=output, stderr=subprocess.STDOUT)
            if root["nodes"][-1]["type"] == "UdpConnector":
                time.sleep(0.4)
                if process.poll() is not None:
                    raise RuntimeError("Peer exited during UDP startup")
            else:
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError("Peer exited during startup")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise RuntimeError("Peer listener timeout")
            raw_input = spec[8] == "raw-ipv4"
            raw_address = local_ipv4() if raw_input else None
            http_port = port if raw_input else free_port()
            env = os.environ.copy()
            env.update({"POC_REMOTE_CONFIG": str(client_path), "POC_HTTP_PORT": str(http_port),
                        "POC_REMOTE_PORT": str(port), "POC_STRESS_BYTES": "65536",
                        "POC_MINIMAL": "1", "POC_SKIP_INVALID": "1"})
            if raw_input:
                env.update({"POC_HTTP_IP": raw_address, "POC_REMOTE_IP": raw_address, "POC_RAW_TRANSPORT": "1"})
            if os.environ.get("SRP_MATRIX_DEBUG") == "1":
                env["POC_DEBUG"] = "1"
            log = self.work / f"{name}-tcp.log"
            status = run_logged([str(self.host_poc)], log, env=env, timeout=45)
            if process.poll() is not None:
                raise RuntimeError(f"Peer exited during TCP traffic: {tail(peer_log)}")
            result["tcp"] = {"passed": status == 0, "error": "" if status == 0 else tail(log)}
            if spec[1] == "http-proxy":
                result["udp"] = {"skipped": "HTTP CONNECT is TCP only"}
            else:
                dns_port = port if raw_input else 0
                thread, failure, dns_address, dns_port = start_udp_responder(dns_port, raw_address)
                env.update({"POC_REMOTE_PORT": str(port), "POC_DNS_IP": dns_address, "POC_DNS_PORT": str(dns_port),
                            "POC_UDP_REPEAT": os.environ.get("SRP_MATRIX_UDP_REPEAT", "1")})
                log = self.work / f"{name}-udp.log"
                status = run_logged([str(self.udp_poc)], log, env=env, timeout=25)
                thread.join(timeout=3)
                if process.poll() is not None:
                    raise RuntimeError(f"Peer exited during UDP traffic: {tail(peer_log)}")
                result["udp"] = {"passed": status == 0 and not failure,
                                  "error": "" if status == 0 and not failure else tail(log) + " ".join(failure)}
            result["teardown"] = stop_peer_status(process)
            process = None
        except Exception as error:
            result["error"] = str(error)
            result["teardown"] = {"passed": False, "returncode": stop_peer(process)}
            process = None
        if result["teardown"].get("returncode") == -11:
            result["teardown"]["error"] = tail(peer_log)
        self.results.append(result)
        print(f"{name}: TCP={result['tcp']} UDP={result['udp']} teardown={result['teardown']}", flush=True)

    def geo_case(self, spec, client_path, direct):
        if spec[0] == "geoip-multi-countries":
            ip, expected_country = "8.8.8.8", "US"
        elif direct:
            ip, expected_country = "5.52.0.1", "IR"
        else:
            ip, expected_country = "192.0.2.1", None
        lookup = shutil.which("mmdblookup") or os.environ.get("SRP_GEOIP_LOOKUP", "/tmp/srp-geoip-lookup")
        lookup_result = subprocess.run([str(lookup), "--file", str(GEO_DATABASE), "--ip", ip],
                                       capture_output=True, text=True)
        if lookup_result.returncode not in (0, 3):
            raise RuntimeError(f"GeoIP lookup failed for {ip}: {lookup_result.stdout} {lookup_result.stderr}")
        matches = lookup_result.returncode == 0 and expected_country is not None and (
            lookup_result.stdout.strip() == expected_country or f'"{expected_country}"' in lookup_result.stdout)
        if matches != direct:
            raise RuntimeError(f"Unexpected GeoIP lookup for {ip}: {lookup_result.stdout}")
        root = json.loads(client_path.read_text())
        port = root["nodes"][-1]["settings"]["port"]
        http_port = free_port()
        unused_port = free_port()
        main_nodes = self.work / f"{spec[0]}-peer.json"
        core = self.work / f"{spec[0]}-core.json"
        for node in root["nodes"]:
            if node["name"] == "direct-local":
                node["settings"].update({"address": "127.0.0.1", "port": http_port if direct else unused_port})
        write_json(client_path, root)
        nodes = peer_nodes(root, port, self.cert, self.key, free_port())
        for node in nodes:
            if node["name"] == "out":
                node["settings"].update({"address": "127.0.0.1", "port": unused_port if direct else http_port})
        write_json(main_nodes, {"name": f"{spec[0]}-peer", "nodes": nodes})
        write_json(core, {"misc": {"workers": 1, "ram-profile": "minimal"}, "configs": [str(main_nodes)]})
        log = self.work / f"{spec[0]}-peer.log"
        process = None
        try:
            with log.open("w") as output:
                process = subprocess.Popen([str(self.peer), f"--config:{core}"], stdout=output, stderr=subprocess.STDOUT)
            time.sleep(0.4)
            if process.poll() is not None:
                raise RuntimeError(tail(log))
            env = os.environ.copy()
            env.update({"POC_REMOTE_CONFIG": str(client_path), "POC_REMOTE_IP": ip,
                        "POC_REMOTE_PORT": str(http_port), "POC_MINIMAL": "1", "POC_SKIP_INVALID": "1"})
            handler = http.server.ThreadingHTTPServer(("127.0.0.1", http_port), http.server.SimpleHTTPRequestHandler)
            thread = threading.Thread(target=handler.serve_forever, daemon=True)
            thread.start()
            test_log = self.work / f"{spec[0]}-traffic.log"
            status = run_logged([str(self.host_poc)], test_log, env=env, timeout=30)
            handler.shutdown()
            handler.server_close()
            thread.join(timeout=3)
            result = {"name": spec[0], "destination": ip,
                      "expected": "direct" if direct else "proxy",
                      "passed": status == 0, "error": "" if status == 0 else tail(test_log),
                      "teardown": stop_peer_status(process)}
            process = None
        except Exception as error:
            result = {"name": spec[0], "passed": False, "error": str(error), "teardown": stop_peer_status(process)}
            process = None
        self.results.append(result)
        print(json.dumps(result), flush=True)

    def run(self):
        selected = CASES
        if self.args.only:
            allowed = set(self.args.only.split(","))
            selected = [case for case in CASES if case[0] in allowed]
        if self.args.geo_only:
            selected = [case for case in CASES if case[0].startswith("geoip-")]
        if not selected:
            raise ValueError("No matching test cases")
        self.build_peer()
        if any(spec[2] in ("tls", "quic", "reality") or spec[0].startswith("geoip-") for spec in selected):
            if run_logged([os.environ.get("SRP_MATRIX_OPENSSL", "openssl"), "req", "-x509",
                           "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                           "-addext", "subjectAltName=DNS:localhost", "-keyout", str(self.key),
                           "-out", str(self.cert), "-days", "1"],
                          self.work / "certificate.log", timeout=30) != 0:
                raise RuntimeError(tail(self.work / "certificate.log"))
        clients = self.generate_clients(selected)
        for spec in selected:
            if spec[0].startswith("geoip-"):
                self.geo_case(spec, clients[spec[0]], spec[0] != "geoip-default-proxy")
            else:
                self.run_case(spec, clients[spec[0]])
        write_json(self.work / "results.json", self.results)
        failures = [result for result in self.results if
                    result.get("passed") is False or result.get("error") or
                    result.get("tcp", {}).get("passed") is False or result.get("udp", {}).get("passed") is False or
                    result["teardown"].get("passed") is False]
        print(f"Work directory: {self.work}")
        print(f"Cases: {len(self.results)}, failures: {len(failures)}")
        return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description="Run app-builder WaterWall combinations with real peer handshakes and data transfer")
    parser.add_argument("--build", action="store_true", help="Build the full upstream peer instead of reusing the existing one")
    parser.add_argument("--only", help="Comma-separated case names")
    parser.add_argument("--geo-only", action="store_true", help="Run only GeoIP traffic tests")
    args = parser.parse_args()
    try:
        return Matrix(args).run()
    except Exception as error:
        print(f"Matrix setup failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
