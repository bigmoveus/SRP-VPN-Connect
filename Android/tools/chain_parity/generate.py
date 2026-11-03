#!/usr/bin/env python3
"""Writes app/src/test/resources/chain_config_parity.json.gz: iOS's answers for a broad corpus of WaterWall profiles.

ChainConfigParityTest checks that the Kotlin port gives the same answers. Run this again after a change to
iOS/Core/SRPCore/SRPWaterWallChainConfig.m. The corpus holds only made-up values and a fixed random seed.
"""
import gzip
import json
import random
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
OUTPUT = REPO / "Android/app/src/test/resources/chain_config_parity.json.gz"
SOURCE = REPO / "iOS/Core/SRPCore"
UUID = "00000000-0000-4000-8000-000000000000"
random.seed(20261103)


def chain(**fields):
    base = {"version": 3, "mode": "chain", "input": "connections", "application": "vless", "mux": False, "outer": "tls",
            "http": "off", "http-version": 1, "obfuscator": False, "carrier": "tcp", "quic-carrier": "datagram", "node-options": {}}
    base.update(fields)
    return base


BASES = [
    chain(), chain(mux=True), chain(outer="reality"), chain(outer="aead"), chain(outer="none"), chain(outer="bgp4"),
    chain(outer="quic"), chain(outer="quic", **{"quic-carrier": "stream"}), chain(outer="quic", mux=True, **{"quic-carrier": "stream"}),
    chain(http="http"), chain(http="websocket"), chain(http="http", **{"http-version": 2}), chain(obfuscator=True),
    chain(carrier="kcp"), chain(bgp4=True), chain(application="vmess"), chain(application="vmess", outer="none"),
    chain(application="trojan"), chain(application="socks5", outer="none"), chain(application="http-proxy"),
    chain(application="http-proxy", outer="quic", **{"quic-carrier": "stream"}), chain(application="http-proxy", outer="none"),
    chain(input="raw-ipv4", application=""), chain(input="raw-ipv4", application="", outer="aead"),
    chain(input="raw-ipv4", application="", outer="quic"), chain(input="raw-ipv4", application="", carrier="kcp", obfuscator=True),
    {"version": 3, "mode": "direct", "node-options": {}}, {"version": 3, "mode": "wireguard", "node-options": {}},
]
POOL = [True, False, 0, 1, -1, 2, 16, 68, 78, 86, 90, 255, 256, 1024, 1200, 1452, 1453, 4096, 16356, 16357, 16384, 65535, 65536, 65537,
        1048576, 2097152, 16777216, 67108864, 67108865, 2147483647, 2147483648, 4294967295, 4294967296, 1.5, 10.0, "", "x", "none", "tcp",
        "udp", "connect", "hard", "loose", "timer", "counter", "fixed-connections-count", "xor", "split", "single", "https", "http", "h2",
        "1", "2", "auto", "wrap", "strict", "packetaddr", "zero", "auto", "aes-gcm", "chacha20", "resolve-domains-and-prefer-ipv4",
        "do-not-resolve-domains", "dest_context->protocol", [], {}, [1], ["h2"], {"a": "b"}, {"a": 1}, None]
SCHEMA = {
    "packet": ["mtu", "udp-idle-timeout-ms", "max-pending-bytes", "max-total-pending-bytes", "fake-dns", "mapdns", "fake_dns",
               "sensitive-mode", "interval-ms", "tolerance-ms", "packet-validation-level", "enabled", "unknown-key"],
    "application": ["protocol", "proto", "first-payload-timeout-ms", "verbose", "domain-strategy", "security", "chunk-masking", "global-padding",
                    "authenticated-length", "encrypted-counter-policy", "send-termination", "packet-encoding", "headers", "max-header-bytes",
                    "header-timeout-ms", "connect-response-timeout-ms", "idle-timeout-ms", "unknown-key"],
    "mux": ["mode", "connection-duration-ms", "connection-capacity", "per-worker-connections-count", "keepalive", "ping-interval", "tolerance-ms",
            "parent-write-buffer-pause-threshold", "parent-write-buffer-resume-threshold", "parent-write-buffer-limit", "max-children",
            "child-buffer-limit", "child-buffer-resume-threshold", "parent-buffer-limit", "detached-buffer-limit", "detached-child-limit",
            "log-main-line-stats", "unknown-key"],
    "http": ["path", "scheme", "method", "user-agent", "http-version", "upgrade", "upgrade-protocol", "upgrade-request-headers",
             "upgrade-response-headers", "headers", "content-type", "websocket-origin", "websocket-subprotocol", "websocket-extensions",
             "http1-mode", "split", "verbose", "unknown-key"],
    "obfuscator": ["method", "xor_key", "skip", "tls_record_header", "tls_header", "unknown-key"],
    "kcp": ["mtu", "fec", "fec-data-shards", "fec-parity-shards", "kcp-nodelay", "kcp-interval-ms", "kcp-resend", "kcp-no-congestion-control",
            "kcp-send-window", "kcp-recv-window", "kcp-initial-cwnd", "kcp-rx-minrto-ms", "kcp-send-buffer-limit", "ping-interval-ms",
            "no-recv-timeout-ms", "unknown-key"],
    "outer": ["alpns", "x25519mlkem768", "fragment", "tls13-record-shaping", "ech-config-list", "ech-sni-trick", "verbose", "algorithm", "method",
              "salt", "kdf-iterations", "max-frame-size", "ca-file", "protocol", "handshake-timeout-ms", "idle-timeout-ms", "max-packet-size",
              "max-buffered-bytes", "max-buffered-buffers", "receive-window-bytes", "unknown-key"],
}
NESTED = {
    ("packet", "fake-dns"): [{"enabled": False}, {"enabled": True, "address": "198.18.0.9", "port": 5353}, {"enabled": 1}, {"address": 1}, {"port": 0},
                             {"port": 65536}, {"cache-size": 262144}, {"cache-size": 262145}, {"ttl": -1}, {"other": 1}, {"netmask": "255.0.0.0"}],
    ("packet", "mapdns"): [{"enabled": True}, {"other": 1}], ("packet", "fake_dns"): [{"enabled": True}],
    ("application", "headers"): [{"X-Test": "1"}, {"Host": "x"}, {"X Bad": "1"}, {"X-Test": "a\u0001b"}, {"X-Test": "a\tb"}, {"": "1"}, {"Proxy-Connection": "x"}],
    ("outer", "alpns"): [["h2"], ["h2", "h2"], [""], ["h2", "http/1.1"], ["x" * 256], [1], "h2", []],
    ("outer", "fragment"): [
        {}, {"mode": "counter"}, {"mode": "timed"}, {"mode": "other", "count": 1, "cuts": []}, {"mode": "counter", "count": 1, "cuts": []},
        {"mode": "counter", "count": 1, "duration-ms": 1, "cuts": []}, {"mode": "timed", "duration-ms": 1, "cuts": []}, {"mode": "timed", "count": 1, "duration-ms": 1, "cuts": []},
        {"mode": "counter", "count": 1, "bypass_chance": 101, "cuts": []}, {"mode": "counter", "count": 1, "wait-for-est": 1, "cuts": []},
        {"mode": "counter", "count": 1, "tls-hello-timeout-ms": 5, "cuts": []}, {"mode": "counter", "count": 1, "tls-hello-fragment": True, "tls-hello-timeout-ms": 5, "cuts": []},
        {"mode": "counter", "count": 1, "cuts": [[1, 0, 100], [2, 0, 100]]}, {"mode": "counter", "count": 1, "cuts": [[2, 0, 100], [2, 0, 100]]}, {"mode": "counter", "count": 1, "cuts": [[0, 0, 100]]},
        {"mode": "counter", "count": 1, "cuts": [[1, -1, 100]]}, {"mode": "counter", "count": 1, "cuts": [[1, 0, 101]]}, {"mode": "counter", "count": 1, "cuts": [[1, 0]]},
        {"mode": "counter", "count": 1, "cuts": [[i + 1, 0, 100] for i in range(65)]}, {"mode": "counter", "count": 1, "other": 1, "cuts": []},
        {"mode": "counter", "count": 4294967296, "cuts": []},
    ],
    ("outer", "tls13-record-shaping"): [
        {}, {"other": 1}, {"scope": {}}, {"scope": {"first-application-records": 1}}, {"scope": {"first-application-records": 1025}, "outcomes": [{"probability": 1, "padding-bytes": 1}]},
        {"scope": {"first-application-records": 1}, "outcomes": []}, {"scope": {"first-application-records": 1}, "outcomes": [{"probability": 1, "padding-bytes": 1}]},
        {"scope": {"first-application-records": 1}, "outcomes": [{"probability": 0, "padding-bytes": 1}]}, {"scope": {"first-application-records": 1}, "outcomes": [{"probability": 60, "padding-bytes": 1}, {"probability": 50, "padding-bytes": 1}]},
        {"scope": {"first-application-records": 1}, "outcomes": [{"probability": 1, "padding-bytes": [1, 4096]}]}, {"scope": {"first-application-records": 1}, "outcomes": [{"probability": 1, "padding-bytes": [5, 1]}]},
        {"scope": {"first-application-records": 1}, "outcomes": [{"probability": 1, "padding-bytes": 4097}]}, {"scope": {"first-application-records": 1}, "outcomes": [{"probability": 1}]},
        {"scope": {"first-application-records": 1}, "outcomes": [{"probability": 1, "delay": {"probability": 50, "ms": 10}}]}, {"scope": {"first-application-records": 1}, "outcomes": [{"probability": 1, "delay": {"probability": 0, "ms": 10}}]},
        {"scope": {"first-application-records": 1}, "outcomes": [{"probability": 1, "delay": {"probability": 50, "ms": [0, 10]}}]}, {"scope": {"first-application-records": 1}, "outcomes": [{"probability": 1, "delay": {"probability": 50, "ms": 1001}}]},
        {"scope": {"first-application-records": 1}, "outcomes": [{"probability": 1, "delay": {"other": 1}}]}, {"scope": {"first-application-records": 1}, "outcomes": [{"probability": 1, "other": 1}]}, {"scope": {"first-application-records": 1}, "outcomes": [1]},
    ],
}
ALGORITHMS = ["chacha20-poly1305", "chacha20poly1305", "chacha20", "chacha", "aes-gcm", "aes-256-gcm", "aes256gcm", "aes256-gcm", "other", ""]


def with_options(base, layer, settings):
    configuration = json.loads(json.dumps(base))
    configuration["node-options"] = {layer: settings}
    return configuration


def secrets_for(configuration):
    application = configuration.get("application")
    secret = {"vless": UUID, "vmess": UUID, "trojan": "trojan-password"}.get(application, "")
    outer = {"reality": "reality-password", "aead": "aead-password"}.get(configuration.get("outer"), "")
    return secret, outer


def case(configuration, **extra):
    secret, outer = secrets_for(configuration if isinstance(configuration, dict) else {})
    item = {"kind": "chain", "configuration": configuration, "server": "server.example.com", "port": 443, "sni": "", "verifyTLS": True,
            "secret": secret, "outerSecret": outer, "options": {}}
    item.update(extra)
    return item


def corpus():
    items = []
    # Every field of the chain itself, mixing good and bad values.
    fields = {
        "mode": ["chain"] * 8 + ["direct", "wireguard", "other", 1, None],
        "input": ["connections"] * 6 + ["raw-ipv4", "raw-ipv4", "other", 1],
        "application": ["vless", "vmess", "trojan", "socks5", "http-proxy", "", "other", 1],
        "mux": [False, False, True, 1, "x"],
        "outer": ["none", "tls", "tls", "reality", "aead", "quic", "bgp4", "other", 1],
        "http": ["off", "off", "off", "http", "websocket", "other", 1],
        "http-version": [1, 1, 2, 3, "1", 1.5],
        "obfuscator": [False, False, True, 1],
        "carrier": ["tcp", "tcp", "kcp", "other", 1],
        "quic-carrier": ["datagram", "stream", "other", 1],
        "bgp4": [False, True, 1],
    }
    for _ in range(9000):
        configuration = {"version": 3, "node-options": {}}
        for key, values in fields.items():
            value = random.choice(values)
            if key == "bgp4" and random.random() < 0.7:
                continue
            if random.random() < 0.01:
                continue
            if value is None:
                continue
            configuration[key] = value
        items.append(case(configuration))
    for base in BASES:
        items.append(case(base))
        for version in [None, 1, 2, 4, "3", 3.0]:
            configuration = dict(base)
            if version is None:
                configuration.pop("version")
            else:
                configuration["version"] = version
            items.append(case(configuration))
        items.append(case(dict(base, other=1)))
        items.append(case(dict(base, **{"node-options": 1})))
        items.append(case(dict(base, **{"node-options": {"packet": 1}})))
        items.append(case(dict(base, **{"node-options": {"other": {}}})))
        # Every node setting with values around its limits.
        for layer, keys in SCHEMA.items():
            for key in keys:
                for value in random.sample(POOL, 8):
                    items.append(case(with_options(base, layer, {key: value})))
                for value in NESTED.get((layer, key), []):
                    items.append(case(with_options(base, layer, {key: value})))
        for key in ["algorithm", "method"]:
            for value in ALGORITHMS:
                items.append(case(with_options(base, "outer", {key: value})))
        # Secrets, proxy credentials and the builder's own inputs.
        for secret in ["", UUID, UUID.replace("-", ""), UUID.upper(), UUID[:-1], "short-id", "x" * 30, "x" * 31, "é" * 16, None]:
            items.append(case(base, secret=secret))
        for outer in ["", "p", "x" * 32, "x" * 33, "é" * 17, None]:
            items.append(case(base, outerSecret=outer))
        for username, secret in [("user", "pass"), ("user", ""), ("", "pass"), ("a:b", "pass"), ("user", "a\nb"), ("x" * 256, "pass"), ("user", "x" * 256)]:
            items.append(case(base, secret=secret, options={"username": username}))
        for extra in [{"server": ""}, {"server": None}, {"port": 0}, {"port": 65536}, {"port": 8443}, {"sni": "cover.example.com"}, {"sni": None}, {"verifyTLS": False}]:
            items.append(case(base, **extra))
        for options in [{"ww_fake_dns": False}, {"ww_fake_dns": True}, {"ww_smart_routing": True}, {"log_level": "debug"}, {"tls_frag": 1}, {"tls_frag": 2},
                        {"tls_frag": 2, "tls_frag_first": 10, "tls_frag_following": 100}, {"tls_frag": 2, "tls_frag_first": 16384}, {"tls_frag": 1, "tls_frag_first": 10},
                        {"tls_frag": 2, "tls_frag_first": 1, "tls_frag_following": 1}, {"ww_geoip_db_path": "/data/GeoLite2-Country.mmdb"}]:
            items.append(case(base, options=options))
    # GeoIP settings.
    for geoip in [{}, 1, {"other": 1}, {"iran-direct": True}, {"iran-direct": False}, {"iran-direct": 1}, {"countries": ["IR"]}, {"countries": ["ir", "tr", "IR"]},
                  {"countries": []}, {"countries": ["IRN"]}, {"countries": [1]}, {"countries": "IR"}, {"update-url": "https://example.com/a.mmdb"},
                  {"update-url": "http://example.com/a.mmdb"}, {"update-url": ""}, {"update-url": " https://example.com"}, {"update-url": "https://u:p@example.com/a"},
                  {"update-url": "https://example.com/a#f"}, {"update-url": "https://"}, {"update-url": 1}, {"update-url": "https://example.com/" + "x" * 2048},
                  {"countries": ["IR"], "update-url": "https://example.com/a.mmdb"}]:
        for base in [chain(), chain(input="raw-ipv4", application=""), {"version": 3, "mode": "direct", "node-options": {}}]:
            for options in [{}, {"ww_geoip_db_path": "/data/GeoLite2-Country.mmdb"}, {"ww_geoip_db_path": "/data/GeoLite2-Country.mmdb", "ww_smart_routing": True}]:
                items.append(case(dict(base, geoip=geoip), options=options))
    # Version 2 profiles migrate.
    items.append(case({"version": 2, "mode": "chain", "input": "connections", "application": "vless", "mux": False, "outer": "tls", "node-options": {}}))
    items.append(case({"version": 2, "mode": "direct", "node-options": {}}))
    # MUX and VMess rules that need two settings together.
    for settings in [{"mode": "timer", "connection-duration-ms": 100}, {"mode": "timer"}, {"mode": "timer", "connection-duration-ms": 100, "connection-capacity": 1},
                     {"mode": "fixed-connections-count", "per-worker-connections-count": 2}, {"mode": "fixed-connections-count"}, {"mode": "fixed-connections-count", "per-worker-connections-count": 2, "connection-capacity": 1},
                     {"connection-capacity": 4}, {"mode": "", "connection-capacity": 4}, {"parent-write-buffer-resume-threshold": 9000000}, {"parent-write-buffer-pause-threshold": 17000000},
                     {"parent-write-buffer-limit": 100}, {"parent-write-buffer-resume-threshold": 0}]:
        items.append(case(with_options(chain(mux=True), "mux", settings)))
    for settings in [{"security": "zero"}, {"security": "zero", "protocol": "tcp"}, {"security": "zero", "proto": "connect", "chunk-masking": True}, {"security": "none", "authenticated-length": True},
                     {"global-padding": True, "chunk-masking": False}, {"global-padding": True}, {"packet-encoding": "packetaddr"}, {"packet-encoding": "packetaddr", "domain-strategy": "resolve-domains-and-prefer-ipv4"},
                     {"packet-encoding": "packetaddr", "domain-strategy": "do-not-resolve-domains"}, {"proto": "udp"}, {"proto": "tcp"}, {"protocol": "tcp", "proto": "udp"}]:
        items.append(case(with_options(chain(application="vmess"), "application", settings)))
    for settings in [{"mtu": 77}, {"mtu": 78}, {"fec": True, "mtu": 85}, {"fec": True, "mtu": 86}, {"fec-data-shards": 200, "fec-parity-shards": 56}, {"fec-data-shards": 200, "fec-parity-shards": 55},
                     {"kcp-initial-cwnd": 129}, {"kcp-initial-cwnd": 128}, {"kcp-send-window": 8, "kcp-initial-cwnd": 9}, {"ping-interval-ms": 30000}, {"ping-interval-ms": 40000, "no-recv-timeout-ms": 50000}, {"no-recv-timeout-ms": 10000}]:
        items.append(case(with_options(chain(carrier="kcp"), "kcp", settings)))
    for settings in [{"max-buffered-bytes": 65536}, {"max-buffered-bytes": 65536, "receive-window-bytes": 65536, "max-buffered-buffers": 2730}, {"max-buffered-buffers": 65536},
                     {"receive-window-bytes": 16777216}, {"protocol": ""}, {"protocol": "h3"}, {"ca-file": ""}, {"ca-file": "/x"}]:
        items.append(case(with_options(chain(outer="quic"), "outer", settings)))
    for settings in [{"http-version": "auto"}, {"http-version": "h2"}, {"http-version": 1}, {"http1-mode": "split"}, {"http1-mode": "split", "http-version": 2}, {"websocket-extensions": "x"},
                     {"headers": {"a": "b"}}, {"headers": {"a": 1}}, {"split": {}}, {"split": 1}, {"path": "/x", "method": "POST", "user-agent": "u"}]:
        for base in [chain(http="http"), chain(http="websocket"), chain(http="http", outer="none"), chain(http="http", **{"http-version": 2})]:
            items.append(case(with_options(base, "http", settings)))
    for settings in [{"skip": "ipv4"}, {"skip": "transport"}, {"skip": "none"}, {"xor_key": 256}, {"xor_key": 0}]:
        for base in [chain(obfuscator=True), chain(input="raw-ipv4", application="", obfuscator=True)]:
            items.append(case(with_options(base, "obfuscator", settings)))
    # WireGuard configurations.
    key = "aGVsbG8taGVsbG8taGVsbG8taGVsbG8taGVsbG8taGU="
    interface = f"[Interface]\nPrivateKey = {key}\nAddress = 10.88.0.2/24\n"
    peer = f"[Peer]\nPublicKey = {key}\nEndpoint = vpn.example.com:51820\n"
    for config in ["", interface, peer, interface + peer, interface + "DNS = 8.8.8.8, 8.8.4.4\n" + peer, interface + peer + "AllowedIPs = 10.0.0.0/8, 192.168.0.0/16\n",
                   interface + peer + "PersistentKeepalive = 25\n", interface + peer + "PersistentKeepalive = 65536\n", interface + peer + "PersistentKeepalive = x\n",
                   interface + peer + "PresharedKey = " + key + "\n", interface + peer + peer.replace("vpn.", "two."), "# comment\n; other\n\n" + interface + "\n" + peer,
                   interface + peer.replace("vpn.example.com:51820", "[2001:db8::1]:51820"), interface + peer.replace(":51820", ":0"), interface + peer.replace(":51820", ""),
                   interface + "[Other]\n" + peer, interface + interface + peer, interface + "no separator\n" + peer, interface + "= value\n" + peer, "[Interface\n", "PrivateKey = x\n",
                   interface.replace("Address = 10.88.0.2/24\n", "") + peer, peer.replace("PublicKey", "OtherKey") + interface, "[INTERFACE]\nPRIVATEKEY = k\nADDRESS = 10.0.0.2\n[PEER]\nPUBLICKEY = p\nENDPOINT = h:1\n",
                   interface + "\r\n".join(peer.splitlines()) + "\r\n", interface + "".join([peer] * 33)]:
        items.append({"kind": "wg-conf", "config": config})
    for values in [("k", "p", "vpn.example.com", 51820, "10.88.0.2/24", 25), ("", "p", "s", 1, "a", 0), ("k", "", "s", 1, "a", 0), ("k", "p", "", 1, "a", 0), ("k", "p", "s", 1, "", 0),
                   ("k", "p", "s", 0, "a", 0), ("k", "p", "s", 65536, "a", 0), ("k", "p", "s", 1, "a", -1), ("k", "p", "s", 1, "a", 65536)]:
        items.append(dict(zip(("privateKey", "serverPublicKey", "server", "port", "clientAddress", "keepalive"), values), kind="wg-keys"))
    return items


def main():
    with tempfile.TemporaryDirectory() as scratch:
        scratch = Path(scratch)
        tool = scratch / "tool"
        subprocess.run(["clang", "-fobjc-arc", "-framework", "Foundation", "-I", str(SOURCE), str(SOURCE / "SRPWaterWallChainConfig.m"), str(HERE / "main.m"), "-o", str(tool)],
                       check=True, capture_output=True)
        items = corpus()
        (scratch / "corpus.json").write_text(json.dumps(items))
        subprocess.run([str(tool), str(scratch / "corpus.json"), str(scratch / "answers.json")], check=True)
        answers = json.loads((scratch / "answers.json").read_text())
    payload = json.dumps(answers, separators=(",", ":"), sort_keys=True).encode()
    OUTPUT.write_bytes(gzip.compress(payload, mtime=0))
    valid = sum(1 for a in answers if a.get("error") is None and a.get("kind") == "chain")
    nodes = sum(1 for a in answers if a.get("nodes"))
    exceptions = sum(1 for a in answers if a.get("exception"))
    print(f"{len(answers)} cases, {valid} valid chains, {nodes} node graphs, {exceptions} exceptions on iOS; {OUTPUT.stat().st_size} bytes")


if __name__ == "__main__":
    main()
