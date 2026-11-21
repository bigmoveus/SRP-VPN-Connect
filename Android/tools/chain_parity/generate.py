#!/usr/bin/env python3
"""Writes app/src/test/resources/chain_config_parity.json.gz: iOS's answers for a broad corpus of WaterWall profiles, of the
form-made configurations (SRPWaterWallChainConfig, with the node chain each converts to) and of the node editor's documents
(SRPWaterWallNodeChain: checks, chain order and branches, the form WaterWall 1.6 takes, edits and the runtime copy for each
input).

ChainConfigParityTest checks that the Kotlin port gives the same answers. Run this again after a change to
iOS/Core/SRPCore/SRPWaterWallChainConfig.m. The corpus holds only made-up values and fixed random seeds.
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
    chain(input="raw-ipv4", application="", outer="none", **{"packet-encryption": True}),
    chain(input="raw-ipv4", application="", outer="quic", **{"packet-encryption": True}),
    chain(input="raw-ipv4", application="", carrier="kcp", outer="none", **{"packet-encryption": True}),
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
    "application": ["protocol", "proto", "first-payload-timeout-ms", "verbose", "domain-strategy", "dns-behaviour", "security", "chunk-masking", "global-padding",
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
    "kcp": ["send-mtu", "mtu", "fec", "fec-data-shards", "fec-parity-shards", "kcp-nodelay", "kcp-interval-ms", "kcp-resend", "kcp-no-congestion-control",
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
    ("application", "dns-behaviour"): [{"resolve": False}, {"resolve": True}, {"resolve": True, "strategy": "prefer-ipv4"}, {"resolve": True, "strategy": "core-settings"},
                                       {"resolve": False, "strategy": "prefer-ipv4"}, {"resolve": True, "strategy": "resolve-domains-and-prefer-ipv4"}, {"resolve": 1},
                                       {}, {"strategy": "only-ipv6"}, {"resolve": True, "mode": "chain"}, {"resolve": True, "strategy": None}],
    ("application", "domain-strategy"): ["do-not-resolve-domains", "resolve-domains-and-prefer-ipv4", "resolve-domains-with-core-settings",
                                         "resolve-domains-and-accept-dns-returned-order", "resolve-domains-and-use-only-ipv6", "prefer-ipv4", None],
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
    if configuration.get("packet-encryption") is True and not outer:
        outer = "packet-password"
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
        "packet-encryption": [False, False, True, 1],
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
    # The DNS resolver option, its server grammar and what it needs from the chain.
    servers = ["1.1.1.1", "1.1.1.1:53", "1.1.1.1:5353", "1.1.1.1:0", "1.1.1.1:65535", "1.1.1.1:65536", "1.1.1.1:00053", "1.1.1.1:", "01.1.1.1", "1.1.1",
               "1.2.3.4.5", "256.1.1.1", "1.1.1.1 ", " 1.1.1.1", "2001:db8::53", "[2001:db8::53]:5353", "[2001:db8::53]", "[1.1.1.1]:53", "[::1]:53x", "[::1]x",
               "::", "::1", "::ffff:1.2.3.4", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9", "1::2::3", "12345::", "1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:7:1.2.3.4",
               ":1::", "1:2:3:4:5:6:7::", "::1.2.3.4", "fe80::1%en0", "fe80::1%1", "1.01.1.1", "0.0.0.0", "00001::", "0001:0002::",
               "::ffff:01.2.3.4", "::FFFF:1.2.3.4", "1:2:3:4:5:6:7:8::", "::1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7::8", "[::1]:", "[::1]:0", "[]:53", "dns.google", "", "x" * 65, "[" + "1" * 70 + "]", "é", 1, None]
    resolvers = [{}, {"mode": "native"}, {"mode": "native", "strategy": "prefer-ipv6"}, {"mode": "native", "servers": ["1.1.1.1"]}, {"mode": "direct"},
                 {"mode": "chain", "servers": []}, {"mode": "chain", "servers": ["1.1.1.1"] * 33}, {"mode": "other"}, {"mode": 1}, {"strategy": "bad"},
                 {"mode": "direct", "servers": "1.1.1.1"}, {"other": 1}, {"mode": "chain", "servers": ["1.1.1.1"], "dns-next": "x"}, 1, [],
                 {"mode": "direct", "servers": ["9.9.9.9", "149.112.112.112:53"], "strategy": "only-ipv4"}]
    resolvers += [{"mode": mode, "servers": [server]} for mode in ["direct", "chain"] for server in servers]
    for resolver in resolvers:
        items.append(case(dict(chain(), **{"domain-resolver": resolver})))
    for resolver in [{"mode": "native"}, {"mode": "direct", "servers": ["1.1.1.1"]}, {"mode": "chain", "servers": ["1.1.1.1", "[2606:4700:4700::1111]:53"]}]:
        for base in BASES:
            items.append(case(dict(base, **{"domain-resolver": resolver})))
            for options in [{"ww_smart_routing": True}, {"ww_geoip_db_path": "/data/GeoLite2-Country.mmdb", "ww_smart_routing": True}]:
                items.append(case(dict(base, geoip={"countries": ["IR"]}, **{"domain-resolver": resolver}), options=options))
        for settings in [{"protocol": "tcp"}, {"proto": "connect"}, {"protocol": "udp"}, {"packet-encoding": "packetaddr"}, {"security": "zero", "protocol": "tcp"}]:
            items.append(case(dict(with_options(chain(application="vmess"), "application", settings), **{"domain-resolver": resolver})))
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
    for settings in [{"mtu": 1350}, {"send-mtu": 117}, {"send-mtu": 118}, {"fec": True, "send-mtu": 125}, {"fec": True, "send-mtu": 126}, {"fec-data-shards": 200, "fec-parity-shards": 56}, {"fec-data-shards": 200, "fec-parity-shards": 55},
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
    items.extend(node_corpus())
    return items


# The node editor's documents (SRPWaterWallNodeChain), with a random source of their own so that the corpus above stays as it was.
NODE_RANDOM = random.Random(20261120)
EXAMPLE = {"name": "Example TLS chain", "nodes": [
    {"name": "input", "type": "HintConnectionIN", "settings": {}, "next": "tls"},
    {"name": "uplink", "type": "TcpConnector", "settings": {"address": "vpn.example.com", "port": 443}},
    {"name": "tls", "type": "TlsClient", "settings": {"sni": "vpn.example.com", "verify": True}, "next": "uplink"}]}
CHAIN_TYPES = ["TlsClient", "VlessClient", "VmessClient", "TrojanClient", "MuxClient", "RealityClient", "EncryptionClient", "StreamFragmenter",
               "HttpClient", "ObfuscatorClient", "KcpClient", "QuicClient", "Bgp4Client", "Router", "DomainResolver", "Socks5Client",
               "HttpProxyClient", "PacketsToStream", "WireGuardDevice", "SpeedTestClient", "UserController"]
LAST_TYPES = ["TcpConnector", "UdpConnector", "TcpUdpConnector", "UdpStatelessSocket", "TlsClient"]
HOSTS = ["vpn.example.com", "192.0.2.1", "edge.example.net", "dest_context->address", "dest_context", "", 5, None]
PORTS = [443, 8443, 1, 65535, 0, 65536, -1, "443", " 443", "\t8443", "\n8443", "443x", "+443", "-443", "x", "", True, False, 443.7, 1000.0,
         99999999999999999999, "99999999999999999999", None, [], {}]
DESTINATIONS = [["geoip:ir"], ["GEOIP:IR", "10.0.0.0/8"], "geoip:us", ["geoip:"], ["10.0.0.0/8"], [5], None, {}, "GeoIP:TR"]
# WaterWall 1.6: a chain that ends at a HalfDuplexClient, the branches that its settings, a Router rule and a dns-next name, and a
# QuicClient as a profile saved for 1.5 has it; then one node's settings changed at a time
BRANCHED = [
    {"name": "input", "type": "HintConnectionIN", "settings": {}, "next": "router"},
    {"name": "router", "type": "Router", "settings": {"rules": [{"source-ips": ["geoip:ir"], "target": "direct"}, {"destination-ip": "10.0.0.0/8"}]}, "next": "quic"},
    {"name": "quic", "type": "QuicClient", "settings": {"sni": "vpn.example.com", "carrier-mode": "stream"}, "next": "half"},
    {"name": "half", "type": "HalfDuplexClient", "settings": {"upload": "up", "download": "down"}},
    {"name": "up", "type": "ObfuscatorClient", "settings": {}, "next": "out"},
    {"name": "out", "type": "TcpConnector", "settings": {"address": "vpn.example.com", "port": 443, "dns-behaviour": {"resolve": True, "dns-next": "dns"}}},
    {"name": "down", "type": "RealityClient", "settings": {}, "next": "far"},
    {"name": "far", "type": "TcpConnector", "settings": {"address": "2001:db8::1", "port": 443}},
    {"name": "direct", "type": "TcpUdpConnector", "settings": {"address": "dest_context->address", "port": "dest_context->port"}},
    {"name": "dns", "type": "TcpUdpConnector", "settings": {"address": "1.1.1.1", "port": 53}}]
BRANCHED_SETTINGS = [
    ("half", {"upload": "up", "download": "gone"}), ("half", {"upload": "input", "download": "down"}), ("half", {"upload": 5, "download": None}), ("half", {}),
    ("out", {"dns-behaviour": {"dns-next": "gone"}}), ("out", {"dns-behaviour": {"dns-next": "input"}}), ("out", {"dns-behaviour": 5}),
    ("out", {"address": "src_context->address", "port": 443}), ("far", {"address": "203.0.113.0/24", "port": 443}),
    ("router", {"rules": [{"target": "gone"}]}), ("router", {"rules": [{"target": "input"}]}), ("router", {"rules": [{"target": 5}, {}]}),
    ("router", {"rules": [{"source-ips": "!!geoip:ir"}], "dns-behaviour": {"dns-next": "dns"}}), ("router", {"rules": [{"destination-ip": "!GeoIP:TR"}]}),
    ("quic", {"carrier-mode": "datagram"}), ("quic", {"carrier-mode": None}), ("quic", {"carrier-mode": 5}), ("quic", {}),
    ("up", {"upload": "gone", "rules": [{"target": "gone"}]})]
# A file in WaterWall's own config syntax: // comments, and $name$ placeholders for the values of "variables"
SYNTAX = ('{\n  // the values to change\n  "variables": {"server": "203.0.113.20", "port": 8443, "tls": {"sni": "vpn.example.com"}},\n'
          '  "name": "price $5 \\" // not a comment",\n  "nodes": [\n    {"name": "input", "type": "HintConnectionIN", "next": "tls"}, // the input\n'
          '    {"name": "tls", "type": "TlsClient", "settings": $tls$, "next": "out"},\n'
          '    {"name": "out", "type": "TcpConnector", "settings": {"address": $server$, "port": $port$}}\n  ]\n}\n')


def node_settings(node_type):
    pick = NODE_RANDOM.random()
    if node_type in ("TcpConnector", "UdpConnector", "TcpUdpConnector") and pick < 0.85:
        settings = {"address": NODE_RANDOM.choice(HOSTS), "port": NODE_RANDOM.choice(PORTS)}
        if NODE_RANDOM.random() < 0.3:
            settings["nodelay"] = True
        return settings
    if node_type == "Router" and pick < 0.8:
        rules = [{"destination-ip": NODE_RANDOM.choice(DESTINATIONS), "target": "direct"} for _ in range(NODE_RANDOM.randint(0, 2))]
        return NODE_RANDOM.choice([{"rules": rules}, {"rules": rules, "geoip-db-path": "/elsewhere/geoip.mmdb"}, {"rules": 5}, {"rules": [5]}, {}])
    if node_type in ("VlessClient", "VmessClient", "TrojanClient", "Socks5Client", "HttpProxyClient") and pick < 0.6:
        # WaterWall 1.5.42 needs the destination of an application node
        return {"uuid": "00000000-0000-4000-8000-000000000000", "address": "dest_context->address", "port": "dest_context->port",
                "protocol": NODE_RANDOM.choice(["tcp", "udp", "connect", "udp-associate", "dest_context->protocol"])}
    return NODE_RANDOM.choice([{}, {"sni": "vpn.example.com", "verify": True}, {"mtu": 1400}])


def random_document():
    """A valid chain in a shuffled array, with off-chain nodes, then a few mistakes of the kinds an import must name."""
    length = NODE_RANDOM.randint(1, 6)
    names = NODE_RANDOM.sample(["input", "tls", "uplink", "mux", "app", "out", "router", "frag", "srp-device", "srp-connections", "srp-device-2",
                                "srp-socks5", "srp-socks5-listener", "srp-http-proxy", "srp-http-listener", "direct", "a", "b"], length + 2)
    hint = {"name": names[0], "type": NODE_RANDOM.choice(["HintConnectionIN", "HintConnectionIN", "HintPacketIN"]), "settings": {}}
    if NODE_RANDOM.random() < 0.1:
        del hint["settings"]
    chain = [hint]
    for index in range(1, length):
        node_type = NODE_RANDOM.choice(LAST_TYPES if index == length - 1 else CHAIN_TYPES)
        node = {"name": names[index], "type": node_type}
        if NODE_RANDOM.random() < 0.9:
            node["settings"] = node_settings(node_type)
        chain.append(node)
    for previous, node in zip(chain, chain[1:]):
        previous["next"] = node["name"]
    nodes = list(chain)
    for name in names[length:length + NODE_RANDOM.randint(0, 2)]:
        node_type = NODE_RANDOM.choice(["TcpUdpConnector", "TcpConnector", "Router", "UdpConnector"])
        nodes.append({"name": name, "type": node_type, "settings": node_settings(node_type)})
    def pick():
        return NODE_RANDOM.choice([node for node in nodes if isinstance(node, dict)])

    mutations = [
        lambda: pick().update(next="missing"),
        lambda: chain[-1].update(next=NODE_RANDOM.choice(chain[1:] or chain).get("name")),
        lambda: pick().update(name=pick().get("name")),
        lambda: nodes.append({"name": "second", "type": NODE_RANDOM.choice(["HintPacketIN", "HintConnectionIN"]), "settings": {}}),
        lambda: hint.update(settings=NODE_RANDOM.choice([{"mtu": 1400}, [], None, {}])),
        lambda: hint.pop("next", None),
        lambda: pick().update(type=NODE_RANDOM.choice(["RawSocket", "TunDevice", "PacketsToConnection", "NEPacketDevice", "", 5, None])),
        lambda: pick().update(settings=NODE_RANDOM.choice([[], "x", 5, None, True])),
        lambda: pick().update(name=NODE_RANDOM.choice(["", 5, None])),
        lambda: pick().update(next=NODE_RANDOM.choice(["", 5, None, [], {}])),
        lambda: nodes.insert(NODE_RANDOM.randint(0, len(nodes)), NODE_RANDOM.choice([5, "node", None, [], {"type": "RawSocket"}])),
        lambda: pick().update(next=hint.get("name")),
        lambda: pick().pop("name", None),
        lambda: pick().pop("type", None),
    ]
    for _ in range(NODE_RANDOM.choice([0, 0, 0, 1, 1, 2])):
        NODE_RANDOM.choice(mutations)()
    NODE_RANDOM.shuffle(nodes)
    document = {"nodes": nodes}
    name = NODE_RANDOM.choice(["Example", "", None, 5, "absent", "absent"])
    if name != "absent":
        document["name"] = name
    return document


def node_corpus():
    items = []
    hint = {"name": "input", "type": "HintConnectionIN", "settings": {}, "next": "out"}
    out = {"name": "out", "type": "TcpConnector", "settings": {"address": "vpn.example.com", "port": 443}}
    fixed = [
        EXAMPLE, [], "x", 1, None, True, {}, {"nodes": {}}, {"nodes": "x"}, {"nodes": None}, {"nodes": []},
        {"nodes": [hint, out]}, {"nodes": [out]}, {"nodes": [hint]}, {"nodes": [hint, out, {"name": "raw", "type": "RawSocket", "settings": {}}]},
        {"nodes": [{"type": "RawSocket"}]}, {"nodes": [{"name": "", "type": "RawSocket"}]}, {"nodes": [5, {"type": "RawSocket"}]},
        {"nodes": [hint, out, {"name": "tun", "type": "TunDevice", "settings": {}, "next": "input"}]},
        {"nodes": [hint, out, {"name": "ptc", "type": "PacketsToConnection", "settings": {}}]}, {"nodes": [hint, out, {"type": "NEPacketDevice"}]},
        {"nodes": [hint, 5]}, {"nodes": [hint, None]}, {"nodes": [hint, []]}, {"nodes": [{"type": "TcpConnector"}]},
        {"nodes": [hint, dict(out, name="")]}, {"nodes": [hint, dict(out, name=5)]}, {"nodes": [hint, dict(out, type="")]}, {"nodes": [hint, dict(out, type=5)]},
        {"nodes": [hint, dict(out, settings=[])]}, {"nodes": [hint, dict(out, settings=None)]}, {"nodes": [hint, dict(out, next="")]}, {"nodes": [hint, dict(out, next=5)]},
        {"nodes": [hint, dict(out, next=None)]}, {"nodes": [hint, out, dict(out, type="TlsClient")]},
        {"nodes": [hint, out, {"name": "second", "type": "HintPacketIN", "settings": {}}]}, {"nodes": [dict(hint, settings={"mtu": 1400}), out]},
        {"nodes": [{k: v for k, v in hint.items() if k != "settings"}, out]}, {"nodes": [hint, dict(out, next="input")]}, {"nodes": [dict(hint, next="input"), out]},
        {"nodes": [hint, {"name": "out", "type": "TlsClient", "settings": {}, "next": "input"}]},
        {"nodes": [hint, {"name": "out", "type": "TlsClient", "next": "loop"}, {"name": "loop", "type": "TlsClient", "next": "out"}]},
        {"nodes": [hint, {"name": "out", "type": "TlsClient", "next": "out"}]}, {"nodes": [dict(hint, next="gone"), out]},
        {"nodes": [dict(hint, type="HintPacketIN"), out]}, {"name": "", "nodes": [hint, out]}, {"name": 5, "nodes": [hint, out]},
        {"nodes": [hint, dict(out, type="UdpConnector")]}, {"nodes": [hint, {"name": "out", "type": "UdpStatelessSocket"}]},
        {"nodes": [hint, {"name": "out", "type": "Router", "settings": {"rules": [{"destination-ip": ["geoip:ir"], "target": "direct"}]}, "next": "app"},
                   {"name": "app", "type": "VlessClient", "settings": {"uuid": "00000000-0000-4000-8000-000000000000", "address": "dest_context->address",
                                                                       "port": "dest_context->port", "protocol": "dest_context->protocol"}, "next": "uplink"},
                   {"name": "uplink", "type": "TcpConnector", "settings": {"address": "vpn.example.com", "port": "8443"}},
                   {"name": "direct", "type": "TcpUdpConnector", "settings": {"address": "dest_context->address", "port": "dest_context->port"}},
                   {"name": "spare", "type": "TcpConnector", "settings": {"address": "spare.example.com", "port": 443}}]},
        {"nodes": BRANCHED},
        # A cycle off the chain, whose names the node added for QUIC over TCP would take
        {"nodes": BRANCHED + [{"name": "udp-over-tcp", "type": "BlackHole", "next": "udp-over-tcp-2"}, {"name": "udp-over-tcp-2", "type": "BlackHole", "next": "udp-over-tcp"}]},
    ]
    fixed += [{"nodes": [dict(node, settings=settings) if node["name"] == name else node for node in BRANCHED]} for name, settings in BRANCHED_SETTINGS]
    documents = fixed + [random_document() for _ in range(3000)]
    for document in documents:
        items.append({"kind": "node-chain", "document": document})
    # A file that starts at its own local proxy takes the hint in its place
    listener = {"name": "socks-listener", "type": "TcpUdpListener", "settings": {"address": "127.0.0.1", "port": 1080}, "next": "socks"}
    socks = {"name": "socks", "type": "Socks5Server", "settings": {}, "next": "out"}
    heads = [[listener, socks], [dict(listener, type="TcpListener"), dict(socks, type="HttpProxyServer")], [listener, dict(socks, type="TlsClient")],
             [listener, dict(socks, next=5)], [dict(listener, next="out")], [hint, listener, socks], [listener, socks, dict(socks)],
             [listener, socks, dict(listener, name="second", next="http"), dict(socks, name="http", type="HttpProxyServer")],
             [listener, socks, {"name": "input", "type": "BlackHole"}], [{"name": "before", "type": "BlackHole", "next": "socks-listener"}, listener, socks],
             [dict(listener, next=None), dict(socks, name=None)], [{"name": "socks-listener", "type": "TcpListener"}, {"type": "Socks5Server", "next": "out"}]]
    texts = [json.dumps({"nodes": head + [out]}) for head in heads] + [json.dumps({"nodes": BRANCHED})]
    texts += [SYNTAX, SYNTAX.replace("\n", "\r\n"), SYNTAX.rstrip() + " // the end", SYNTAX.replace("8443", "null"), SYNTAX.replace('"name":', "$port$:", 1),
              "[] // a list", '{"nodes": [] // none\n}', '{"nodes": [], "x": $a$}', '{"variables": [1], "nodes": [], "x": $a$}',
              '{"variables": {"a": $b$, "b": 1}, "x": $a$, "nodes": ' + json.dumps([hint, out]) + "}", json.dumps({"variables": {"a": 1}, "nodes": [hint, out]})]
    texts += [SYNTAX.replace("$port$", broken) for broken in ["$missing$", "$port", "$$", '$po"rt$', "$po\\rt$", "$server$$port$", "$ port $"]]
    texts.append(SYNTAX.replace("$tls$", "$zeta$").replace("$port$", "$alpha$"))   # two undefined: the first by name is the one named
    # Numbers no double can hold, a key written twice (the first value stays), and values that fill in past what a file may hold
    texts += [SYNTAX.replace("8443", number) for number in ["1e999", "-1e999", "1e308", "123456789012345678901234567890"]]
    texts += ['{"nodes": ' + json.dumps([hint, out]) + ', "nodes": []}', '{"variables": {"a": 1}, "variables": {"a": 2}, "x": $a$, "nodes": ' + json.dumps([hint, out]) + "}"]
    texts += ['{"variables": {"big": "' + "x" * 1024 + '"}, "nodes": ' + json.dumps([hint, out]) + ', "notes": [' + ",".join(["$big$"] * count) + "]}"
              for count in (2, 1025)]
    # One comma after the last member or element is accepted, as Apple's reader takes it; any other stray comma is not
    plain = json.dumps({"nodes": [hint, out]})
    texts += [plain[:-1] + ",}", plain[:-2] + ",]}", plain[:-2] + " , ]\n,\n}", plain[:-1] + ",,}", plain[:-2] + ",,]}", "{," + plain[1:],
              plain.replace("[", "[,", 1), plain.replace('"settings": {}', '"settings": {"a": [1, 2,], "b": {"c": true,},}', 1),
              plain.replace('"settings": {}', '"settings": {"a": [,]}', 1)]
    # A \u escape is four hex digits, and half of a surrogate pair alone is refused; the hint keeps its empty settings
    texts += [plain.replace('"vpn.example.com"', '"' + escape + '"', 1) for escape in
              ["\\ud800", "\\udc00", "\\ud83d\\ude00", "\\uD83D\\uDE00", "\\ud800\\u0041", "\\ud83dx", "\\ud83d\\ud83d", "a\\ud83d", "\\u00e9", "\\u-123",
               "\\u+123", "\\u12", "\\u12g4", "\\u0661"]]
    for text in ["", "{", "[]", "{}", "1", "\"x\"", "null", "true", json.dumps(EXAMPLE), "﻿" + json.dumps(EXAMPLE), json.dumps(EXAMPLE) + " ",
                 "{\"nodes\": [", "{\"nodes\": [] }", "{\"nodes\": [{\"name\": \"input\", \"type\": \"HintConnectionIN\", \"next\": \"out\"}]}", None] + texts:
        items.append({"kind": "node-json", "json": text})
    valid = [EXAMPLE] + [document for document in documents if is_valid_document(document)][:160]
    added = [{"name": "added", "type": "StreamFragmenter", "settings": {}}, {"name": "added", "type": "StreamFragmenter", "next": "elsewhere"},
             {"name": "uplink", "type": "TlsClient"}, {"type": "StreamFragmenter"}, {"name": "input2", "type": "HintPacketIN", "settings": {}}]
    for document in valid[:60]:
        for node in [n for n in document["nodes"] if isinstance(n, dict)] + [{"name": "nowhere"}]:
            name = node.get("name")
            items.append({"kind": "node-edit", "document": document, "operation": "delete", "name": name})
            items.append({"kind": "node-edit", "document": document, "operation": "insert", "name": name, "node": NODE_RANDOM.choice(added)})
            for replacement in [dict(node, settings={"sni": "edge.example.net"}), dict(node, name="renamed"), dict(node, name="uplink"),
                                dict(node, type="HintPacketIN"), {k: v for k, v in node.items() if k != "next"}]:
                items.append({"kind": "node-edit", "document": document, "operation": "replace", "name": name, "node": replacement})
    clashes = [dict(EXAMPLE, nodes=EXAMPLE["nodes"] + [{"name": name, "type": "StreamFragmenter", "settings": {}}])
               for name in ["srp-device", "srp-connections", "srp-socks5", "srp-socks5-listener", "srp-http-proxy", "srp-http-listener", "srp-device-2"]]
    clashes.append(dict(EXAMPLE, nodes=EXAMPLE["nodes"] + [{"name": "srp-device", "type": "StreamFragmenter"}, {"name": "srp-device-2", "type": "StreamFragmenter"}]))
    clashes.append(dict(EXAMPLE, nodes=EXAMPLE["nodes"] + [{"name": "meter", "type": "SpeedTestClient", "settings": {}}]))
    packets = dict(EXAMPLE, nodes=[dict(EXAMPLE["nodes"][0], type="HintPacketIN")] + EXAMPLE["nodes"][1:])
    for document in [EXAMPLE, packets] + clashes + valid[1:61] + documents[:20]:
        if not isinstance(document, dict):
            continue
        for input_name in ["tun", "socks5", "http", "other"]:
            for fake_dns in [True, False]:
                for path in [None, "/data/GeoIP/GeoLite2-Country.mmdb", ""]:
                    addresses = NODE_RANDOM.choice([{}, {"vpn.example.com": "192.0.2.10"}, {"vpn.example.com": "192.0.2.10", "192.0.2.1": "192.0.2.1",
                                                                                              "edge.example.net": "198.51.100.7", "spare.example.com": "203.0.113.9"}])
                    items.append({"kind": "node-runtime", "document": document, "input": input_name, "fakeDNS": fake_dns,
                                  "geoIPDatabasePath": path, "addresses": addresses})
    return items


def is_valid_document(document):
    """Roughly the editor's checks, to pick documents worth editing; iOS gives the real answer."""
    if not isinstance(document, dict) or not isinstance(document.get("nodes"), list):
        return False
    nodes = document["nodes"]
    if not all(isinstance(n, dict) and isinstance(n.get("name"), str) and n["name"] and isinstance(n.get("type"), str) and n["type"] for n in nodes):
        return False
    names = [n["name"] for n in nodes]
    return len(set(names)) == len(names) and sum(n["type"] in ("HintConnectionIN", "HintPacketIN") for n in nodes) == 1


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
