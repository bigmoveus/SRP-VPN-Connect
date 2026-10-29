#!/usr/bin/env python3
import argparse
import concurrent.futures
import copy
import itertools
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading
import time

from matrix import (Matrix, ROOT, UUID, OUTER_SECRET, GEO_DATABASE, free_port, local_ipv4,
                    main_chain, peer_nodes, run_logged, start_udp_responder,
                    stop_peer_status, tail, write_json)


def spec(name, app, outer="none", mux=False, http="off", obfuscator=False,
         carrier="tcp", quic="datagram", input_mode="connections", http_version=1,
         mode="chain", node_options=None):
    return (name, app, outer, mux, http, obfuscator, carrier, quic, input_mode,
            http_version, mode, node_options or {})


def advanced_specs():
    result = []
    def add(name, layer, options, app="vmess", outer="none", input_mode="connections", mux=False, carrier="tcp"):
        result.append(spec(name, app, outer, mux=mux, carrier=carrier,
                           input_mode=input_mode, node_options={layer: options}))
    for security in ("aes-128-gcm", "chacha20-poly1305", "auto", "none"):
        add(f"adv-vmess-security-{security}", "application", {"security": security})
    add("adv-vmess-security-zero", "application", {"security": "zero", "protocol": "tcp"})
    add("adv-vmess-masking-padding", "application", {
        "security": "chacha20-poly1305", "chunk-masking": True,
        "global-padding": True, "authenticated-length": True})
    add("adv-vmess-counter-strict", "application", {"encrypted-counter-policy": "strict"})
    add("adv-vmess-no-termination", "application", {"send-termination": False})
    add("adv-vmess-packetaddr", "application", {
        "packet-encoding": "packetaddr", "domain-strategy": "resolve-domains-and-use-only-ipv4"})
    add("adv-vmess-udp", "application", {"protocol": "udp"})
    add("adv-packet-budget", "packet", {"max-pending-bytes": 8192, "max-total-pending-bytes": 65536})
    add("adv-packet-fake-dns", "packet", {"fake-dns": {
        "enabled": True, "address": "198.18.0.2", "network": "100.64.0.0",
        "netmask": "255.192.0.0", "cache-size": 256, "ttl": 1}})
    for mode, options in (("timer", {"connection-duration-ms": 61000}),
                          ("counter", {"connection-capacity": 1}),
                          ("fixed-connections-count", {"per-worker-connections-count": 1})):
        add(f"adv-mux-{mode}", "mux", dict(options, mode=mode), outer="tls", mux=True)
    add("adv-mux-keepalive", "mux", {"keepalive": True, "ping-interval": 1000}, outer="tls", mux=True)
    add("adv-tls-alpn", "outer", {"alpns": ["http/1.1"]}, outer="tls")
    add("adv-tls-fragment", "outer", {"fragment": {
        "mode": "counter", "count": 1, "tls-hello-fragment": True,
        "tls-hello-timeout-ms": 1000, "cuts": [[32, 0, 100]]}}, outer="tls")
    add("adv-tls-record-shaping", "outer", {"tls13-record-shaping": {
        "scope": {"first-application-records": 2},
        "outcomes": [{"probability": 100, "padding-bytes": 64}]}}, outer="tls")
    add("adv-reality-aes", "outer", {"algorithm": "aes-256-gcm"}, outer="reality")
    add("adv-aead-aes", "outer", {"algorithm": "aes-256-gcm", "max-frame-size": 16356}, outer="aead")
    add("adv-quic-buffers", "outer", {"max-buffered-bytes": 2097152,
        "max-buffered-buffers": 1024, "receive-window-bytes": 1048576,
        "handshake-timeout-ms": 10000, "idle-timeout-ms": 30000}, outer="quic")
    add("adv-http1-split", "http", {"http1-mode": "split"}, outer="tls")
    add("adv-http-headers", "http", {"path": "/matrix", "user-agent": "SRP-Matrix",
        "headers": {"X-Test": "WaterWall"}}, outer="tls")
    add("adv-kcp-fec", "kcp", {"mtu": 1350, "fec": True, "fec-data-shards": 10,
        "fec-parity-shards": 3, "kcp-nodelay": True, "kcp-interval-ms": 20}, carrier="kcp")
    add("adv-kcp-windows", "kcp", {"kcp-send-window": 128, "kcp-recv-window": 128,
        "kcp-initial-cwnd": 16, "kcp-send-buffer-limit": 256}, carrier="kcp")
    add("adv-obfuscator-skip", "obfuscator", {"xor_key": 90, "skip": "ipv4"}, outer="tls")
    result[-1] = result[-1][:4] + (True,) + result[-1][5:]
    add("adv-raw-validation", "packet", {"packet-validation-level": "hard"},
        app="", outer="aead", input_mode="raw-ipv4")
    result.append(spec("geoip-direct-country", "vless", "tls"))
    result.append(spec("geoip-default-proxy", "vless", "tls"))
    result.append(spec("geoip-multi-countries", "vless", "tls"))
    return result


def candidate_specs():
    index = 0
    for values in itertools.product(("connections", "raw-ipv4"),
                                    ("vless", "vmess", "trojan", "socks5", "http-proxy", ""),
                                    (False, True), ("none", "tls", "reality", "aead", "quic", "bgp4"),
                                    ("off", "http", "websocket"), (False, True), ("tcp", "kcp"),
                                    ("datagram", "stream"), (False, True), (1, 2)):
        input_mode, app, mux, outer, http, obfuscator, carrier, quic, bgp4, version = values
        index += 1
        name = f"ww-{index:05d}-{app or 'raw'}-{outer}"
        item = spec(name, app, outer, mux, http, obfuscator, carrier, quic,
                    input_mode, version, node_options={"bgp4": True} if bgp4 else {})
        yield item
    yield spec("direct-diagnostics", "", mode="direct")
    yield spec("wireguard-native", "", mode="wireguard")
    yield from advanced_specs()


def builder_input(item, port):
    name, app, outer, mux, http, obfuscator, carrier, quic, input_mode, version, mode, options = item
    configuration = {"version": 3, "mode": mode, "node-options": options}
    if mode == "chain":
        configuration.update({"input": input_mode, "application": app, "mux": mux,
            "outer": outer, "http": http, "http-version": version,
            "obfuscator": obfuscator, "carrier": carrier, "quic-carrier": quic})
    entry = {"id": name, "configuration": configuration, "server": "127.0.0.1",
             "port": port, "sni": "localhost", "verifyTLS": False,
             "options": {"ww_fake_dns": True}}
    if app in ("vless", "vmess", "trojan"):
        entry["secret"] = UUID
    if outer in ("reality", "aead"):
        entry["outerSecret"] = OUTER_SECRET
    if name.startswith("geoip-"):
        configuration["geoip"] = {"countries": ["IR", "US", "TR"]} if name == "geoip-multi-countries" else {"countries": ["IR", "TR"] if name == "geoip-direct-country" else ["IR"]}
        entry["options"]["ww_geoip_db_path"] = str(GEO_DATABASE)
    return entry


class SupportedMatrix(Matrix):
    def __init__(self, args):
        super().__init__(args)
        self.root = ROOT
        self.wireguard_peers = {}
        self.wireguard_udp_clients = {}
        self.summary = {}
        self.write_lock = threading.Lock()

    def generate_clients(self, selected):
        inputs = self.work / "builder-input.json"
        output = self.work / "builder-output.json"
        write_json(inputs, [builder_input(item, free_port()) for item in selected])
        env = os.environ.copy()
        env.update({"TEST_RUNNER_SRP_MATRIX_INPUT": str(inputs),
                    "TEST_RUNNER_SRP_MATRIX_OUTPUT": str(output),
                    "TEST_RUNNER_SRP_MATRIX_VALIDATE": "1"})
        command = ["xcodebuild", "test", "-workspace", str(self.root / "SRP-VPN-Connect.xcworkspace"),
                   "-scheme", "SRP-VPN-ConnectTestsMac", "-destination", "platform=macOS",
                   "-only-testing:SRP-VPN-ConnectTestsMac/SROptionsTests/testWaterWallMatrixGenerationForLocalTesting"]
        if run_logged(command, self.work / "builder.log", env=env, timeout=300) != 0:
            raise RuntimeError(tail(self.work / "builder.log"))
        generated = json.loads(output.read_text())["cases"]
        if len(generated) != len(selected):
            raise RuntimeError("Validator returned an incomplete matrix")
        clients = {}
        excluded = []
        for item, result in zip(selected, generated):
            if not result["supported"]:
                excluded.append({"id": result["id"], "configuration": result["configuration"],
                                 "reason": result["reason"]})
                continue
            path = self.work / f"{result['id']}-client.json"
            root = result["nodes"]
            write_json(path, root)
            clients[item[0]] = path
        self.summary = {"identified": len(selected), "supported": len(clients),
                        "validator_excluded": len(excluded)}
        write_json(self.work / "validator-results.json",
                   {"summary": self.summary, "excluded": excluded})
        return clients

    def wireguard_peer(self, name):
        if name in self.wireguard_peers:
            return self.wireguard_peers[name]
        def keypair():
            private = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout.strip()
            public = subprocess.run(["wg", "pubkey"], input=private, capture_output=True,
                                    text=True, check=True).stdout.strip()
            return private, public
        client_private, client_public = keypair()
        udp_private, udp_public = keypair()
        server_private, server_public = keypair()
        def client_config(private, address):
            return (f"[Interface]\nPrivateKey = {private}\nAddress = {address}/32\n"
                    f"[Peer]\nPublicKey = {server_public}\nAllowedIPs = 0.0.0.0/0\n"
                    f"Endpoint = 127.0.0.1:{self.args.port}\nPersistentKeepalive = 0\n")
        nodes = [
            {"name": "udp", "type": "UdpStatelessSocket", "settings": {
                "listen-address": "127.0.0.1", "source-ip": "127.0.0.1",
                "listen-port": self.args.port}, "next": "wg"},
            {"name": "wg", "type": "WireGuardDevice", "settings": {
                "privatekey": server_private,
                "peers": [{"publickey": public, "allowedips": address + "/32",
                           "endpoint": "127.0.0.1:9", "persistentkeepalive": 0}
                          for public, address in ((client_public, "10.99.0.2"),
                                                 (udp_public, "10.99.0.3"))]}, "next": "ptc"},
            {"name": "ptc", "type": "PacketsToConnection", "settings": {
                "mtu": 1420, "max-pending-bytes": 65536, "max-total-pending-bytes": 4194304}, "next": "router"},
            {"name": "router", "type": "Router", "settings": {"resolve-domains": False}, "next": "out"},
            {"name": "out", "type": "TcpUdpConnector", "settings": {
                "address": "dest_context->address", "port": "dest_context->port",
                "domain-strategy": "prefer-ipv4", "nodelay": True}}
        ]
        for index, node in enumerate(nodes[:-1]):
            node["next"] = nodes[index + 1]["name"]
        self.wireguard_peers[name] = {"client": client_config(client_private, "10.99.0.2"),
                                      "udp_client": client_config(udp_private, "10.99.0.3"),
                                      "nodes": nodes}
        return self.wireguard_peers[name]

    def build_peer_config(self, item, client_path):
        name, app, outer, mux, http, obfuscator, carrier, quic, input_mode, version, mode, options = item
        if mode == "wireguard":
            nodes = copy.deepcopy(self.wireguard_peer(name)["nodes"])
            nodes[0]["settings"]["listen-port"] = self.args.port
            for path in {client_path, self.wireguard_udp_clients.get(name, client_path)}:
                root = json.loads(path.read_text())
                for peer in root["nodes"][1]["settings"]["peers"]:
                    peer["endpoint"] = f"127.0.0.1:{self.args.port}"
                write_json(path, root)
            return nodes
        root = json.loads(client_path.read_text())
        if mode != "direct":
            root["nodes"][-1]["settings"]["port"] = self.args.port
            write_json(client_path, root)
        port = self.args.port
        nodes = peer_nodes(root, port, self.cert, self.key, self.args.cover_port)
        for node in nodes:
            if node["type"] == "VmessServer":
                source = next(n for n in main_chain(root["nodes"]) if n["type"] == "VmessClient")
                settings = source["settings"]
                protocol = settings.get("protocol")
                if protocol in ("udp", "udp-associate"):
                    node["settings"].update({"connect": False, "udp": True})
                elif protocol in ("tcp", "connect"):
                    node["settings"].update({"connect": True, "udp": False})
                for field in ("encrypted-counter-policy", "send-termination", "verbose"):
                    if field in settings:
                        node["settings"][field] = settings[field]
            if node["type"] == "PacketsToConnection":
                source = next(n for n in root["nodes"] if n["type"] == "PacketsToConnection")
                node["settings"] = copy.deepcopy(source["settings"])
                node["settings"].pop("fake-dns", None)
            if node["type"] == "StreamToPackets":
                source = next(n for n in root["nodes"] if n["type"] == "PacketsToStream")
                if "packet-validation-level" in source["settings"]:
                    node["settings"]["packet-validation-level"] = source["settings"]["packet-validation-level"]
        return nodes

    def start_peer(self, item, client_path):
        name, app, outer, mux, http, obfuscator, carrier, quic, input_mode, version, mode, options = item
        if mode == "direct":
            return None, None, None
        root = json.loads(client_path.read_text())
        main_nodes = self.work / f"{name}-peer.json"
        core = self.work / f"{name}-core.json"
        configs = [str(main_nodes)]
        write_json(main_nodes, {"name": name + "-peer", "nodes": self.build_peer_config(item, client_path)})
        if outer == "reality":
            cover = self.work / f"{name}-cover.json"
            write_json(cover, {"name": "cover-peer", "nodes": [
                {"name": "listener", "type": "TcpListener", "settings": {
                    "address": "127.0.0.1", "port": self.args.cover_port}, "next": "tls"},
                {"name": "tls", "type": "TlsServer", "settings": {
                    "cert-file": str(self.cert), "key-file": str(self.key)}, "next": "blackhole"},
                {"name": "blackhole", "type": "BlackHole", "settings": {"mode": "passive"}}]})
            configs.append(str(cover))
        write_json(core, {"misc": {"workers": 1, "ram-profile": "minimal", "splice": False,
                                    "try-enabling-bbr": False, "tcp-tune": False}, "configs": configs})
        log = self.work / f"{name}-peer.log"
        output = log.open("w")
        process = subprocess.Popen([str(self.peer), f"--config:{core}"], stdout=output, stderr=subprocess.STDOUT)
        output.close()
        udp = mode == "wireguard" or carrier == "kcp" or (outer == "quic" and quic == "datagram")
        if udp:
            time.sleep(0.5)
            if process.poll() is not None:
                raise RuntimeError("Peer exited during UDP startup: " + tail(log))
        else:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("Peer exited during startup: " + tail(log))
                try:
                    with socket.create_connection(("127.0.0.1", self.args.port), timeout=0.2):
                        return process, log, root
                except OSError:
                    time.sleep(0.05)
            raise RuntimeError("Peer listener timeout")
        return process, log, root

    def udp_case(self, item, client_path):
        name, app, outer, mux, http, obfuscator, carrier, quic, input_mode, version, mode, options = item
        root = json.loads(client_path.read_text())
        application_node = next((node for node in root["nodes"] if node["type"] in ("VmessClient", "VlessClient")), None)
        protocol = application_node["settings"].get("protocol") if application_node else None
        connector = root["nodes"][-1]["type"] if mode != "wireguard" else "TcpUdpConnector"
        if app == "http-proxy" or input_mode == "raw-ipv4" or (connector != "TcpUdpConnector" and protocol not in ("udp", "udp-associate")):
            reason = "Raw packet-to-stream carries TCP only" if input_mode == "raw-ipv4" else f"Application UDP is unavailable through {connector}"
            return {"status": "not-applicable", "reason": reason}
        if protocol in ("tcp", "connect"):
            return {"status": "not-applicable", "reason": "Application protocol is fixed to TCP"}
        expected = self.args.duration * 10
        remote_dns = os.environ.get("SRP_MATRIX_REMOTE_UDP") == "1"
        remote_port = os.environ.get("SRP_MATRIX_DNS_PORT")
        address = os.environ.get("SRP_MATRIX_DNS_IP") or local_ipv4()
        if remote_dns:
            thread = None
            failure = []
            dns_port = int(remote_port or "28481")
        else:
            thread, failure, address, dns_port = start_udp_responder(0, address, expected=expected)
        env = os.environ.copy()
        udp_client = self.wireguard_udp_clients.get(name, client_path) if mode == "wireguard" else client_path
        env.update({"POC_REMOTE_CONFIG": str(udp_client), "POC_REMOTE_PORT": str(self.args.port),
                    "POC_DNS_IP": address, "POC_DNS_PORT": str(dns_port),
                    "POC_UDP_REPEAT": str(expected), "POC_UDP_DURATION": str(self.args.duration),
                    "POC_MINIMAL": "1"})
        if mode == "wireguard":
            env["POC_SOURCE_IP"] = "10.99.0.3"
        log = self.work / f"{name}-udp.log"
        started = time.monotonic()
        try:
            code = run_logged([str(self.udp_poc)], log, env=env,
                              timeout=max(self.args.duration * 3, self.args.duration + 60))
            if thread is not None:
                thread.join(timeout=3)
            text = log.read_text(errors="replace")
            match = re.search(r"UDP responses: (\d+) of (\d+) in (\d+) ms", text)
            timing = re.search(r"UDP timing: average_rtt_ms=([0-9.]+) max_rtt_ms=([0-9.]+) average_jitter_ms=([0-9.]+)", text)
            resources = re.search(r"Resources: max_rss_kib=(\d+) user_cpu_ms=(\d+) system_cpu_ms=(\d+)", text)
            responses = int(match[1]) if match else 0
            passed = (code == 0 and not failure and match is not None and responses == expected and
                      time.monotonic() - started >= self.args.duration)
            return {"status": "passed" if passed else "failed", "duration_s": round(time.monotonic() - started, 3),
                    "requests": expected, "responses": responses,
                    "loss_percent": round(100.0 * (expected - responses) / expected, 3),
                    "average_rtt_ms": float(timing[1]) if timing else None,
                    "max_rtt_ms": float(timing[2]) if timing else None,
                    "average_jitter_ms": float(timing[3]) if timing else None,
                    "resources": {"max_rss_kib": int(resources[1]), "user_cpu_ms": int(resources[2]),
                                  "system_cpu_ms": int(resources[3])} if resources else {},
                    "error": "" if passed else tail(log) + " ".join(failure)}
        except Exception as error:
            return {"status": "failed", "error": str(error), "duration_s": round(time.monotonic() - started, 3)}

    def run_case(self, item, client_path):
        name, app, outer, mux, http, obfuscator, carrier, quic, input_mode, version, mode, options = item
        if name.startswith("geoip-"):
            return self.geo_case(item, client_path, name != "geoip-default-proxy")
        result = {"id": name, "configuration": builder_input(item, self.args.port)["configuration"],
                  "client_path": str(client_path), "peer_path": str(self.work / f"{name}-peer.json"),
                  "tcp": {}, "udp": {}, "teardown": {}}
        process = None
        try:
            process, peer_log, root = self.start_peer(item, client_path)
            protocol = options.get("application", {}).get("protocol")
            if protocol in ("udp", "udp-associate"):
                result["tcp"] = {"status": "not-applicable", "reason": "Application protocol is fixed to UDP"}
            else:
                env = os.environ.copy()
                http_port = self.args.port if input_mode == "raw-ipv4" else free_port()
                env.update({"POC_REMOTE_CONFIG": str(client_path), "POC_HTTP_PORT": str(http_port),
                            "POC_REMOTE_PORT": str(http_port if mode == "wireguard" else self.args.port),
                            "POC_STRESS_DURATION": str(self.args.duration),
                            "POC_CONNECTIONS": os.environ.get("SRP_MATRIX_CONNECTIONS", "1"),
                            "POC_SERVER_BPS": os.environ.get("SRP_MATRIX_SERVER_BPS", "262144"),
                            "POC_MINIMAL": "1", "POC_SKIP_INVALID": "1"})
                if input_mode == "raw-ipv4" or mode == "wireguard":
                    address = local_ipv4()
                    env.update({"POC_HTTP_IP": address, "POC_REMOTE_IP": address, "POC_RAW_TRANSPORT": "1"})
                if mode == "wireguard":
                    env["POC_SOURCE_IP"] = "10.99.0.2"
                tcp_log = self.work / f"{name}-tcp.log"
                started = time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                udp_future = executor.submit(self.udp_case, item, client_path)
                if protocol not in ("udp", "udp-associate"):
                    code = run_logged([str(self.host_poc)], tcp_log, env=env, timeout=self.args.duration + 90)
            if protocol not in ("udp", "udp-associate"):
                text = tcp_log.read_text(errors="replace") if tcp_log.exists() else ""
                match = re.search(r"received (\d+) of (\d+) response bytes in (\d+) ms", text)
                ready = re.search(r"Tunnel ready: (\d+) ms", text)
                resources = re.search(r"Resources: max_rss_kib=(\d+) user_cpu_ms=(\d+) system_cpu_ms=(\d+)", text)
                passed = code == 0 and match is not None and int(match[1]) >= int(match[2]) and int(match[3]) >= self.args.duration * 1000
                result["tcp"] = {"status": "passed" if passed else "failed", "duration_s": round(time.monotonic() - started, 3),
                                  "bytes": int(match[1]) if match else 0,
                                  "requests": int(env["POC_CONNECTIONS"]) if passed else 0,
                                  "connect_time_ms": int(ready[1]) if ready else None,
                                  "bytes_per_second": round(int(match[1]) * 1000 / int(match[3]), 3) if match and int(match[3]) > 0 else 0,
                                  "resources": {"max_rss_kib": int(resources[1]), "user_cpu_ms": int(resources[2]),
                                                "system_cpu_ms": int(resources[3])} if resources else {},
                                  "error": "" if passed else tail(tcp_log)}
            if udp_future is not None:
                result["udp"] = udp_future.result()
            if process is not None and process.poll() is not None:
                raise RuntimeError("Peer exited during traffic: " + tail(peer_log))
            result["teardown"] = stop_peer_status(process)
            process = None
        except Exception as error:
            result["error"] = str(error)
            result["teardown"] = {"passed": False, "returncode": stop_peer_status(process)["returncode"]}
            process = None
        result["status"] = "failed" if (result.get("error") or
            result["tcp"].get("status") == "failed" or result["udp"].get("status") == "failed" or
            not result["teardown"].get("passed", False)) else "passed"
        self.results.append(result)
        print(f"{name}: {result['status']} TCP={result['tcp']} UDP={result['udp']} teardown={result['teardown']}", flush=True)
        return result

    def geo_case(self, item, client_path, direct):
        name = item[0]
        ip = (getattr(self, "host", None) or os.environ.get("SRP_MATRIX_DIRECT_IP", "46.31.77.252")) if direct else "192.0.2.1"
        country = "TR" if direct else None
        lookup = os.environ.get("SRP_GEOIP_LOOKUP", "/tmp/srp-geoip-lookup")
        lookup_result = subprocess.run([lookup, "--file", str(GEO_DATABASE), "--ip", ip], capture_output=True, text=True)
        matches = lookup_result.returncode == 0 and country is not None and (lookup_result.stdout.strip() == country or f'"{country}"' in lookup_result.stdout)
        if matches != direct:
            raise RuntimeError(f"Unexpected GeoIP lookup for {ip}: {lookup_result.stdout}")
        root = json.loads(client_path.read_text())
        http_port = free_port()
        unused_port = free_port()
        for node in root["nodes"]:
            if node["name"] == "direct-local":
                node["settings"].update({"address": ip if direct else "127.0.0.1", "port": 80 if direct else unused_port})
        write_json(client_path, root)
        main_nodes = self.work / f"{name}-peer.json"
        nodes = self.build_peer_config(item, client_path)
        for node in nodes:
            if node["name"] == "out":
                node["settings"].update({"address": "127.0.0.1", "port": unused_port if direct else http_port})
        write_json(main_nodes, {"name": name + "-peer", "nodes": nodes})
        core = self.work / f"{name}-core.json"
        write_json(core, {"misc": {"workers": 1, "ram-profile": "minimal"}, "configs": [str(main_nodes)]})
        process = None
        result = {"id": name, "destination": ip, "expected": "direct" if direct else "proxy",
                  "client_path": str(client_path), "peer_path": str(main_nodes), "tcp": {}, "teardown": {}}
        try:
            with (self.work / f"{name}-peer.log").open("w") as output:
                process = subprocess.Popen([str(self.peer), f"--config:{core}"], stdout=output, stderr=subprocess.STDOUT)
            time.sleep(0.5)
            env = os.environ.copy()
            env.update({"POC_REMOTE_CONFIG": str(client_path), "POC_REMOTE_IP": ip,
                        "POC_REMOTE_PORT": str(80 if direct else http_port), "POC_MINIMAL": "1", "POC_SKIP_INVALID": "1",
                        "POC_RAW_TRANSPORT": "1", "POC_STRESS_DURATION": str(self.args.duration),
                        "POC_SERVER_BPS": "180000", "POC_STRESS_BYTES": "16777216",
                        "POC_HTTP_PORT": str(http_port), "POC_HTTP_PATH": "/throughput.bin"})
            if direct:
                env["POC_EXTERNAL_HTTP"] = "1"
            log = self.work / f"{name}-tcp.log"
            started = time.monotonic()
            status = run_logged([str(self.host_poc)], log, env=env, timeout=self.args.duration + 60)
            text = log.read_text(errors="replace")
            match = re.search(r"received (\d+) of (\d+) response bytes in (\d+) ms", text)
            ready = re.search(r"Tunnel ready: (\d+) ms", text)
            resources = re.search(r"Resources: max_rss_kib=(\d+) user_cpu_ms=(\d+) system_cpu_ms=(\d+)", text)
            passed = status == 0 and match is not None and int(match[1]) >= int(match[2])
            result["tcp"] = {"status": "passed" if passed else "failed", "duration_s": round(time.monotonic() - started, 3),
                              "bytes": int(match[1]) if match else 0,
                              "connect_time_ms": int(ready[1]) if ready else None,
                              "bytes_per_second": round(int(match[1]) * 1000 / int(match[3]), 3) if match and int(match[3]) > 0 else 0,
                              "resources": {"max_rss_kib": int(resources[1]), "user_cpu_ms": int(resources[2]),
                                            "system_cpu_ms": int(resources[3])} if resources else {},
                              "error": "" if passed else tail(log)}
            result["teardown"] = stop_peer_status(process)
            process = None
        except Exception as error:
            result["error"] = str(error)
            result["teardown"] = stop_peer_status(process)
            process = None
        result["status"] = "passed" if not result.get("error") and result["tcp"]["status"] == "passed" and result["teardown"].get("passed") else "failed"
        self.results.append(result)
        print(json.dumps(result), flush=True)
        return result

    def prepare_clients(self, selected):
        wireguard = [item for item in selected if item[10] == "wireguard"]
        for item in wireguard:
            peer = self.wireguard_peer(item[0])
            path = self.work / f"{item[0]}-wireguard.conf"
            path.write_text(peer["client"])
            path.chmod(0o600)
        entries = [builder_input(item, self.args.port) for item in selected]
        for item, entry in zip(selected, entries):
            if item[10] == "wireguard":
                entry["wireguard"] = self.wireguard_peer(item[0])["client"]
        udp_entries = []
        for item in wireguard:
            entry = builder_input(item, self.args.port)
            entry["id"] = item[0] + "-udp"
            entry["wireguard"] = self.wireguard_peer(item[0])["udp_client"]
            udp_entries.append(entry)
        inputs = self.work / "builder-input.json"
        write_json(inputs, entries + udp_entries)
        env = os.environ.copy()
        env.update({"TEST_RUNNER_SRP_MATRIX_INPUT": str(inputs),
                    "TEST_RUNNER_SRP_MATRIX_OUTPUT": str(self.work / "builder-output.json"),
                    "TEST_RUNNER_SRP_MATRIX_VALIDATE": "1"})
        command = ["xcodebuild", "test", "-workspace", str(self.root / "SRP-VPN-Connect.xcworkspace"),
                   "-scheme", "SRP-VPN-ConnectTestsMac", "-destination", "platform=macOS",
                   "-only-testing:SRP-VPN-ConnectTestsMac/SROptionsTests/testWaterWallMatrixGenerationForLocalTesting"]
        if run_logged(command, self.work / "builder.log", env=env, timeout=300) != 0:
            raise RuntimeError(tail(self.work / "builder.log"))
        generated = json.loads((self.work / "builder-output.json").read_text())["cases"]
        if len(generated) != len(entries) + len(udp_entries):
            raise RuntimeError("Validator returned an incomplete matrix")
        clients = {}
        excluded = []
        for item, result in zip(selected, generated):
            if not result["supported"]:
                excluded.append({"id": result["id"], "configuration": result["configuration"], "reason": result["reason"]})
                continue
            path = self.work / f"{item[0]}-client.json"
            write_json(path, result["nodes"])
            clients[item[0]] = path
        for item, result in zip(wireguard, generated[len(selected):]):
            if not result["supported"]:
                raise RuntimeError(f"WireGuard UDP client was rejected: {result['reason']}")
            path = self.work / f"{item[0]}-udp-client.json"
            write_json(path, result["nodes"])
            self.wireguard_udp_clients[item[0]] = path
        self.summary = {"identified": len(selected), "supported": len(clients), "validator_excluded": len(excluded)}
        write_json(self.work / "validator-results.json", {"summary": self.summary, "excluded": excluded})
        print(f"Work directory: {self.work}; matrix: {self.summary}", flush=True)
        return clients

    def run_isolated_case(self, item, client_path):
        result = {"id": item[0], "configuration": builder_input(item, self.args.port)["configuration"],
                  "client_path": str(client_path), "rounds": []}
        for round_index in range(self.args.rounds):
            runner = copy.copy(self)
            runner.args = copy.copy(self.args)
            runner.args.port = self.args.port if getattr(self.args, "fixed_port", False) else free_port()
            runner.args.cover_port = self.args.cover_port if getattr(self.args, "fixed_port", False) else free_port()
            runner.work = self.work / item[0] / f"round-{round_index + 1}"
            runner.work.mkdir(parents=True)
            runner.results = []
            round_result = runner.run_case(item, client_path)
            round_result["round"] = round_index + 1
            result["rounds"].append(round_result)
            if round_result["status"] == "failed":
                break
        result["status"] = "passed" if len(result["rounds"]) == self.args.rounds and all(
            item["status"] == "passed" for item in result["rounds"]) else "failed"
        if result["rounds"]:
            result["peer_path"] = result["rounds"][-1].get("peer_path", "")
        return result

    def record_result(self, result):
        with self.write_lock:
            self.results.append(result)
            progress = {"completed_cases": len(self.results),
                        "completed_rounds": sum(len(case.get("rounds", [])) for case in self.results)}
            write_json(self.work / "results.json", {"summary": self.summary, "progress": progress, "cases": self.results})

    def summarize_results(self):
        failures = [result for result in self.results if result["status"] == "failed"]
        rounds = [round_result for result in self.results for round_result in result.get("rounds", [])]
        passed_rounds = sum(round_result["status"] == "passed" for round_result in rounds)
        self.summary.update({
            "executed": len(self.results), "passed": len(self.results) - len(failures), "failed": len(failures),
            "supported_untested": self.summary["supported"] - len(self.results),
            "expected_rounds": self.summary["supported"] * self.args.rounds,
            "rounds_executed": len(rounds), "rounds_passed": passed_rounds,
            "rounds_failed": len(rounds) - passed_rounds,
            "rounds_untested": self.summary["supported"] * self.args.rounds - len(rounds),
        })
        return failures

    def run(self):
        selected = list(candidate_specs())
        if self.args.only:
            allowed = set(self.args.only.split(","))
            selected = [item for item in selected if item[0] in allowed or item[1] in allowed or item[10] in allowed]
        if not selected:
            raise ValueError("No matching test cases")
        self.args.cover_port = free_port()
        self.args.port = free_port()
        if self.args.wireguard_only:
            selected = [item for item in selected if item[10] == "wireguard"]
        clients = self.prepare_clients(selected)
        if self.args.enumerate_only:
            return 0
        self.build_peer()
        if any(item[2] in ("tls", "quic", "reality") or item[0].startswith("geoip-") for item in selected if item[0] in clients):
            if run_logged([os.environ.get("SRP_MATRIX_OPENSSL", "openssl"), "req", "-x509",
                           "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                           "-addext", "subjectAltName=DNS:localhost", "-keyout", str(self.key),
                           "-out", str(self.cert), "-days", "1"], self.work / "certificate.log", timeout=30) != 0:
                raise RuntimeError(tail(self.work / "certificate.log"))
        runnable = [item for item in selected if item[0] in clients]
        if self.args.workers == 1:
            for item in runnable:
                self.record_result(self.run_isolated_case(item, clients[item[0]]))
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.workers) as executor:
                pending = {executor.submit(self.run_isolated_case, item, clients[item[0]]): item for item in runnable}
                for future in concurrent.futures.as_completed(pending):
                    item = pending[future]
                    try:
                        result = future.result()
                    except Exception as error:
                        result = {"id": item[0], "status": "failed", "error": str(error)}
                    self.record_result(result)
        failures = self.summarize_results()
        write_json(self.work / "results.json", {"summary": self.summary, "cases": self.results})
        print(f"Completed: {self.summary}", flush=True)
        return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description="Enumerate with the app validator and test real WaterWall client/peer combinations")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--only", help="Comma-separated case IDs, application names, or modes")
    parser.add_argument("--enumerate-only", action="store_true")
    parser.add_argument("--duration", type=int, default=90)
    parser.add_argument("--wireguard-only", action="store_true")
    parser.add_argument("--workers", type=int, default=1, help="Independent host-test workers; each has its own ports and logs")
    parser.add_argument("--rounds", type=int, default=3, help="Independent timed rounds per supported combination")
    args = parser.parse_args()
    if args.duration < 1 or args.duration > 3600:
        parser.error("Duration must be between 1 and 3600 seconds")
    if args.workers < 1 or args.workers > 16:
        parser.error("Workers must be between 1 and 16")
    if args.rounds < 1 or args.rounds > 10:
        parser.error("Rounds must be between 1 and 10")
    try:
        return SupportedMatrix(args).run()
    except Exception as error:
        print(f"Matrix setup failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
