#!/usr/bin/env python3
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit, urlunsplit

from matrix import UUID, GEO_DATABASE, run_logged, tail, write_json
from supported_matrix import SupportedMatrix, candidate_specs, builder_input


class DeviceMatrix(SupportedMatrix):
    def __init__(self, args):
        super().__init__(args)
        self.host = os.environ.get("SRP_TEST_SSH_HOST")
        self.binary = os.environ.get("SRP_TEST_PEER_BINARY")
        self.url = os.environ.get("SRP_TEST_HTTP_URL")
        self.device = os.environ.get("SRP_DEVICE_ID", "00008150-0005753622D8C01C")
        self.team = os.environ.get("DEVELOPMENT_TEAM", "F92335CVXH")
        self.configuration = os.environ.get("SRP_TEST_CONFIGURATION", "Debug")
        if self.configuration not in ("Debug", "Release"):
            raise ValueError("SRP_TEST_CONFIGURATION must be Debug or Release")
        self.derived_data = Path(os.environ.get("SRP_TEST_DERIVED_DATA") or
                                 tempfile.mkdtemp(prefix="srp-waterwall-device-matrix-"))
        self.scheme = os.environ.get("SRP_TEST_SCHEME", "SRPWWLive")
        self.control = os.environ.get("SRP_TEST_SSH_CONTROL", "none")
        # A key avoids handing the harness a password; without one, the askpass flow is used.
        self.identity = os.environ.get("SRP_TEST_SSH_IDENTITY")
        # The test credentials are public fixtures, so isolated ports can be limited to one client.
        source = os.environ.get("SRP_TEST_ALLOWED_SOURCE")
        self.allowed_source = str(ipaddress.IPv4Address(source)) if source else None
        self.remote_dir = "/tmp/srp-device-matrix"
        self.remote_binary = self.remote_dir + "/Waterwall"
        self.remote_pid = self.remote_dir + "/peer.pid"
        self.args.fixed_port = True
        self.health_started = False
        self.stress_https_started = False
        self.stress_https_firewall = False
        self.udp_started = False
        self.trace_udp = os.environ.get("SRP_TEST_TRACE_UDP_SERVER") == "1"
        self.udp_port = int(os.environ.get("SRP_TEST_UDP_PORT", "28482" if self.trace_udp else "28481"))
        if not 1 <= self.udp_port <= 65535:
            raise ValueError("SRP_TEST_UDP_PORT must be a valid port")

    def ssh_environment(self):
        env = os.environ.copy()
        if self.identity:
            return env
        env.setdefault("SSH_ASKPASS", "/tmp/srp-waterwall-askpass.sh")
        env.setdefault("SSH_ASKPASS_REQUIRE", "force")
        env.setdefault("DISPLAY", ":0")
        return env

    def ssh_options(self):
        if self.identity:
            return ["-o", f"ControlPath={self.control}", "-o", "StrictHostKeyChecking=yes",
                    "-o", "ConnectTimeout=15", "-o", "BatchMode=yes",
                    "-o", "IdentitiesOnly=yes", "-i", self.identity]
        return ["-o", f"ControlPath={self.control}", "-o", "StrictHostKeyChecking=yes",
                "-o", "ConnectTimeout=15", "-o", "PreferredAuthentications=password",
                "-o", "PubkeyAuthentication=no", "-o", "KbdInteractiveAuthentication=no"]

    def firewall_match(self):
        return f"ip saddr {self.allowed_source} " if self.allowed_source else ""

    def ssh(self, command, timeout=60):
        if not self.host:
            raise RuntimeError("SRP_TEST_SSH_HOST is required")
        result = subprocess.run(["ssh", *self.ssh_options(), "root@" + self.host, command],
                                capture_output=True, text=True, timeout=timeout, env=self.ssh_environment())
        if result.returncode != 0:
            raise RuntimeError("Remote command failed: " + (result.stderr or result.stdout)[-2500:])
        return result.stdout

    def scp(self, source, destination, timeout=90):
        result = subprocess.run(["scp", *self.ssh_options(),
                                 str(source), "root@" + self.host + ":" + str(destination)],
                                capture_output=True, text=True, timeout=timeout, env=self.ssh_environment())
        if result.returncode != 0:
            raise RuntimeError("SCP failed: " + result.stderr[-2500:])

    def download(self, source, destination, timeout=90):
        result = subprocess.run(["scp", *self.ssh_options(),
                                 "root@" + self.host + ":" + str(source), str(destination)],
                                capture_output=True, text=True, timeout=timeout, env=self.ssh_environment())
        if result.returncode != 0:
            raise RuntimeError("SCP failed: " + result.stderr[-2500:])

    def prepare_remote_peer(self):
        binary = Path(self.binary)
        if not binary.is_file():
            raise RuntimeError("SRP_TEST_PEER_BINARY must name a local Linux peer binary")
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        remote = shlex.quote(self.remote_binary)
        self.ssh("mkdir -p " + shlex.quote(self.remote_dir))
        output = self.ssh(f"if [ -f {remote} ]; then sha256sum {remote}; fi")
        remote_digest = output.split()[0] if output.split() else ""
        if remote_digest != digest:
            self.stop_remote_peer()
            uploading = self.remote_binary + ".uploading"
            self.scp(binary, uploading)
            self.ssh(f"chmod 755 {shlex.quote(uploading)} && mv {shlex.quote(uploading)} {remote}")
            output = self.ssh(f"sha256sum {remote}")
            remote_digest = output.split()[0] if output.split() else ""
        if remote_digest != digest:
            raise RuntimeError("The uploaded peer hash does not match the local binary")
        self.ssh(f"test -x {remote}")

    def start_remote_peer(self, item, client_path):
        name, app, outer, mux, http, obfuscator, carrier, quic, input_mode, version, mode, options = item
        if mode == "direct":
            return None
        peer = self.remote_dir + "/peer.json"
        core = self.remote_dir + "/core.json"
        nodes = self.build_peer_config(item, client_path)
        nodes[0]["settings"]["address"] = self.host
        if mode == "wireguard":
            nodes[0]["settings"].update({"listen-address": self.host, "source-ip": self.host})
        for node in nodes:
            if node["type"] == "Socks5Server":
                node["settings"]["ipv4"] = self.host
            if os.environ.get("SRP_TEST_PEER_DEBUG") == "1" and node["type"] in ("HttpServer", "VmessServer", "Socks5Server", "HttpProxyServer"):
                node["settings"]["verbose"] = True
            for key in ("cert-file", "key-file"):
                if key in node["settings"]:
                    node["settings"][key] = self.remote_dir + ("/cert.pem" if key == "cert-file" else "/key.pem")
        local_peer = self.work / f"{name}-peer.json"
        local_core = self.work / f"{name}-core.json"
        configs = [peer]
        if outer == "reality":
            cover = self.remote_dir + "/cover.json"
            configs.append(cover)
            write_json(self.work / f"{name}-cover.json", {"name": "cover-peer", "nodes": [
                {"name": "listener", "type": "TcpListener", "settings": {
                    "address": "127.0.0.1", "port": self.args.cover_port}, "next": "tls"},
                {"name": "tls", "type": "TlsServer", "settings": {
                    "cert-file": self.remote_dir + "/cert.pem", "key-file": self.remote_dir + "/key.pem"},
                 "next": "blackhole"},
                {"name": "blackhole", "type": "BlackHole", "settings": {"mode": "passive"}}]})
            self.scp(self.work / f"{name}-cover.json", cover)
        write_json(local_peer, {"name": name + "-peer", "nodes": nodes})
        core_config = {"misc": {"workers": 1, "ram-profile": "minimal", "splice": False,
                                 "try-enabling-bbr": False, "tcp-tune": False},
                       "configs": configs}
        if os.environ.get("SRP_TEST_PEER_DEBUG") == "1":
            core_config["log"] = {channel: {"loglevel": "DEBUG", "console": True}
                                  for channel in ("core", "network", "dns", "internal")}
        write_json(local_core, core_config)
        self.ssh("mkdir -p " + shlex.quote(self.remote_dir))
        self.scp(local_peer, peer)
        self.scp(local_core, core)
        if outer in ("tls", "reality", "quic"):
            self.scp(self.cert, self.remote_dir + "/cert.pem")
            self.scp(self.key, self.remote_dir + "/key.pem")
            self.ssh("test -s " + shlex.quote(self.remote_dir + "/cert.pem") +
                     " && test -s " + shlex.quote(self.remote_dir + "/key.pem"))
        self.stop_remote_peer()
        for protocol in ("t", "u"):
            listeners = self.ssh(f"ss -H -l{protocol}n 'sport = :{self.args.port}'")
            if listeners.strip():
                raise RuntimeError(f"Port {self.args.port} is occupied by an unrelated listener")
        self.ensure_remote_firewall()
        if app == "socks5":
            rules = self.ssh("nft list chain ip filter ufw-user-input")
            if "SRP_Isolated_Tests_UDP" not in rules:
                self.ssh(f"nft add rule ip filter ufw-user-input {self.firewall_match()}udp dport 32768-60999 "
                         "counter accept comment SRP_Isolated_Tests_UDP")
        command = ("nohup {binary} --config:{core} > {dir}/peer.log 2>&1 < /dev/null & echo $! > {pid}").format(
            binary=shlex.quote(self.remote_binary), core=core, dir=self.remote_dir, pid=self.remote_pid)
        if os.environ.get("SRP_TEST_TRACE_PEER") == "1":
            command = ("nohup strace --kill-on-exit -f -tt -e trace=connect,sendto,recvfrom,sendmsg,recvmsg,getpeername,getsockopt -s 64 "
                       "-o /tmp/srp-device-matrix/trace.log " + command.removeprefix("nohup "))
        self.ssh(command)
        udp = mode == "wireguard" or carrier == "kcp" or (outer == "quic" and quic == "datagram")
        if not udp:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if not self._remote_peer_pids():
                    raise RuntimeError("Remote peer exited before opening its listener")
                try:
                    with socket.create_connection((self.host, self.args.port), timeout=0.5):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("Remote peer did not open its listener")
        if not self._remote_peer_pids():
            raise RuntimeError("Remote peer exited during startup")
        return self.remote_pid

    def ensure_remote_firewall(self):
        rules = self.ssh("nft list chain ip filter ufw-user-input")
        for protocol in ("tcp", "udp"):
            if f"{protocol} dport {self.args.port}" not in rules:
                self.ssh(f"nft add rule ip filter ufw-user-input {self.firewall_match()}{protocol} dport {self.args.port} "
                         "counter accept comment SRP_Isolated_Tests")

    def stop_remote_firewall(self):
        rules = self.ssh("nft -a list chain ip filter ufw-user-input")
        for line in rules.splitlines():
            if "SRP_Isolated_Tests" not in line:
                continue
            match = re.search(r"(?:tcp|udp) dport (\d+)", line)
            handle = re.search(r" handle (\d+)$", line)
            if "SRP_Isolated_Tests_UDP" in line and handle:
                self.ssh(f"nft delete rule ip filter ufw-user-input handle {int(handle[1])}")
                continue
            allowed_ports = {self.args.port, self.udp_port} if self.trace_udp else {self.args.port}
            if match and handle and int(match[1]) in allowed_ports:
                self.ssh(f"nft delete rule ip filter ufw-user-input handle {int(handle[1])}")

    def _remote_peer_pids(self):
        # WaterWall 1.5 re-executes itself with --ww-internal-* arguments and keeps --config last.
        config = f"--config:{self.remote_dir}/core.json"
        pids = []
        for line in self.ssh("ps -eo pid=,args=").splitlines():
            fields = line.strip().split(maxsplit=1)
            if len(fields) != 2:
                continue
            args = fields[1].split()
            if args[0] == self.remote_binary and args[-1] == config:
                pids.append(int(fields[0]))
        return pids

    def stop_remote_peer(self, item=None):
        if item is not None and item[10] == "direct":
            return
        for signal, timeout in (("INT", 10), ("TERM", 5)):
            pids = self._remote_peer_pids()
            if not pids:
                break
            joined = " ".join(str(pid) for pid in pids)
            self.ssh(f"kill -{signal} {joined} 2>/dev/null || true")
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline and self._remote_peer_pids():
                time.sleep(0.2)
        if self._remote_peer_pids():
            raise RuntimeError("The isolated remote peer did not stop")
        if item is not None:
            for attempt in range(3):
                try:
                    self.download(self.remote_dir + "/peer.log", self.work / f"{item[0]}-peer.log", timeout=15)
                    break
                except Exception as error:
                    if attempt == 2:
                        print(f"Could not retrieve peer log for {item[0]}: {error}", flush=True)
                    else:
                        time.sleep(0.25)

    def ensure_udp_server(self):
        if not self.trace_udp:
            return
        if self.ssh(f"ss -H -lun 'sport = :{self.udp_port}'").strip():
            raise RuntimeError(f"UDP diagnostic port {self.udp_port} is already occupied")
        self.ssh("mkdir -p " + shlex.quote(self.remote_dir))
        self.scp("/tmp/srp-trace-udp-responder.py", self.remote_dir + "/udp_responder.py")
        rules = self.ssh("nft list chain ip filter ufw-user-input")
        if f"udp dport {self.udp_port}" not in rules:
            self.ssh(f"nft add rule ip filter ufw-user-input {self.firewall_match()}udp dport {self.udp_port} "
                     "counter accept comment SRP_Isolated_Tests")
        command = ("nohup python3 {dir}/udp_responder.py > {dir}/udp-server.log 2>&1 < /dev/null & "
                   "echo $! > {dir}/udp.pid").format(dir=self.remote_dir)
        self.ssh(command)
        self.udp_started = True
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.ssh(f"ss -H -lun 'sport = :{self.udp_port}'").strip():
                return
            time.sleep(0.1)
        raise RuntimeError("The isolated UDP diagnostic listener did not start")

    def stop_udp_server(self):
        if not self.udp_started:
            return
        try:
            self.download(self.remote_dir + "/udp-server.log", self.work / "udp-server.log")
        except Exception as error:
            print(f"Could not retrieve UDP diagnostic log: {error}", flush=True)
        pid_file = self.remote_dir + "/udp.pid"
        command = ("if [ -f {pid} ]; then p=$(cat {pid}); "
                   "if [ \"$(ps -p \"$p\" -o args=)\" = \"python3 {dir}/udp_responder.py\" ]; then "
                   "kill -TERM \"$p\"; sleep 1; "
                   "if [ \"$(ps -p \"$p\" -o args=)\" = \"python3 {dir}/udp_responder.py\" ]; then exit 1; fi; fi; fi"
                   ).format(pid=shlex.quote(pid_file), dir=self.remote_dir)
        self.ssh(command)
        self.udp_started = False

    def effective_configuration(self, item):
        configuration = dict(builder_input(item, self.args.port)["configuration"])
        if os.environ.get("SRP_TEST_WW_NODE_OPTIONS"):
            node_options = json.loads(os.environ["SRP_TEST_WW_NODE_OPTIONS"])
            if not isinstance(node_options, dict):
                raise ValueError("SRP_TEST_WW_NODE_OPTIONS must contain a JSON object")
            configuration["node-options"] = node_options
        return configuration

    def environment(self, item, client_path):
        name, app, outer, mux, http, obfuscator, carrier, quic, input_mode, version, mode, options = item
        entry = builder_input(item, self.args.port)
        config = self.effective_configuration(item)
        env = os.environ.copy()
        env.update({
            "TEST_RUNNER_SRP_BGP4_LIVE_TEST": "1",
            "TEST_RUNNER_SRP_BGP4_SERVER": self.host,
            "TEST_RUNNER_SRP_BGP4_PORT": str(self.args.port),
            "TEST_RUNNER_SRP_BGP4_UUID": entry.get("secret", UUID),
            "TEST_RUNNER_SRP_BGP4_CARRIER": carrier,
            "TEST_RUNNER_SRP_WW_APPLICATION": app,
            "TEST_RUNNER_SRP_WW_OUTER": outer,
            "TEST_RUNNER_SRP_WW_SNI": "localhost",
            "TEST_RUNNER_SRP_WW_INSECURE": "1",
            "TEST_RUNNER_SRP_WW_LOG_LEVEL": os.environ.get("SRP_TEST_WW_LOG_LEVEL", "0"),
            "TEST_RUNNER_SRP_WW_OUTER_SECRET": entry.get("outerSecret", ""),
            "TEST_RUNNER_SRP_WW_CONFIG_JSON": json.dumps(config, separators=(",", ":")),
            "TEST_RUNNER_SRP_WW_TEST_ID": name,
            "TEST_RUNNER_SRP_WW_STRESS_BYTES": "16777216",
            "TEST_RUNNER_SRP_WW_STRESS_CONNECTIONS": os.environ.get("SRP_TEST_WW_STRESS_CONNECTIONS", "4"),
            "TEST_RUNNER_SRP_STRESS_DURATION": str(self.args.duration),
            "TEST_RUNNER_SRP_STRESS_ROUNDS": "1",
            "TEST_RUNNER_SRP_WW_STRESS_URL": self.url,
            "TEST_RUNNER_SRP_AUTO_RECONNECT": "0",
            "TEST_RUNNER_SRP_ON_SLEEP": "2",
            "TEST_RUNNER_SRP_FULL_DUPLEX_TEST": os.environ.get("SRP_TEST_WW_FULL_DUPLEX", "0"),
            "TEST_RUNNER_SRP_NETWORK_TRANSITION_TEST": os.environ.get("SRP_TEST_WW_NETWORK_TRANSITION", "0"),
        })
        if name.startswith("geoip-"):
            destination = "waterwall.srp.services"
            parts = urlsplit(self.url)
            port = 28480
            env["TEST_RUNNER_SRP_WW_STRESS_URL"] = urlunsplit((parts.scheme, f"{destination}:{port}", parts.path, parts.query, parts.fragment))
        if mode == "wireguard":
            env["TEST_RUNNER_SRP_WW_WG_CONFIG"] = self.wireguard_peer(name)["client"].replace(
                "127.0.0.1", self.host)
        client_root = json.loads(client_path.read_text())
        connector = "TcpUdpConnector" if mode in ("direct", "wireguard") else client_root["nodes"][-1]["type"]
        application_node = next((node for node in client_root["nodes"] if node["type"] in ("VmessClient", "VlessClient")), None)
        protocol = application_node["settings"].get("protocol") if application_node else None
        application_udp = protocol in ("udp", "udp-associate")
        udp = app != "http-proxy" and input_mode == "connections" and (connector == "TcpUdpConnector" or application_udp)
        env["TEST_RUNNER_SRP_WW_TCP_STRESS"] = "0" if application_udp else "1"
        env["TEST_RUNNER_SRP_WW_UDP_STRESS"] = "1" if udp else "0"
        env["TEST_RUNNER_SRP_WW_UDP_PORT"] = str(self.udp_port)
        if os.environ.get("SRP_FETCH_LOGS_ON_FAILURE") == "1":
            env["TEST_RUNNER_SRP_FETCH_LOGS_ON_FAILURE"] = "1"
        if os.environ.get("SRP_TEST_PINNED_CERT"):
            env["TEST_RUNNER_SRP_WW_STRESS_TRUSTED_CERT"] = os.environ["SRP_TEST_PINNED_CERT"]
        return env

    def ensure_health_server(self):
        if self.ssh("ss -H -ltn 'sport = :80'").strip():
            return
        script = self.work / "health_server.py"
        script.write_text(
            "import http.server\n"
            "import os\n"
            "import time\n\n"
            "class Handler(http.server.SimpleHTTPRequestHandler):\n"
            "    def do_GET(self):\n"
            "        if self.path.split(\"?\")[0] != \"/throughput.bin\":\n"
            "            self.send_response(204)\n"
            "            self.end_headers()\n"
            "            return\n"
            "        with open(\"/tmp/srp-throughput-public/throughput.bin\", \"rb\") as source:\n"
            "            size = os.fstat(source.fileno()).st_size\n"
            "            self.send_response(200)\n"
            "            self.send_header(\"Content-Type\", \"application/octet-stream\")\n"
            "            self.send_header(\"Content-Length\", str(size))\n"
            "            self.end_headers()\n"
            "            started = time.monotonic()\n"
            "            sent = 0\n"
            "            while True:\n"
            "                chunk = source.read(16384)\n"
            "                if not chunk:\n"
            "                    break\n"
            "                sent += len(chunk)\n"
            "                self.wfile.write(chunk)\n"
            "                time.sleep(max(0, started + sent / 180000 - time.monotonic()))\n\n"
            "http.server.ThreadingHTTPServer((\"0.0.0.0\", 80), Handler).serve_forever()\n"
        )
        self.ssh("mkdir -p " + shlex.quote(self.remote_dir))
        self.scp(script, self.remote_dir + "/health_server.py")
        self.ssh("nohup python3 /tmp/srp-device-matrix/health_server.py > /tmp/srp-device-matrix/health.log "
                 "2>&1 < /dev/null & echo $! > /tmp/srp-device-matrix/health.pid")
        self.health_started = True
        time.sleep(0.2)
        self.ssh("python3 -c 'import socket; s=socket.create_connection((\"127.0.0.1\", 80), timeout=2); s.close()'")

    def stop_health_server(self):
        if not self.health_started:
            return
        self.ssh("if [ -f /tmp/srp-device-matrix/health.pid ]; then p=$(cat /tmp/srp-device-matrix/health.pid); "
                 "case \"$(ps -p \"$p\" -o args=)\" in *health_server.py*) kill -TERM \"$p\" 2>/dev/null || true;; esac; fi")
        self.health_started = False

    def start_direct_server(self):
        self.ensure_health_server()
        lookup = shutil.which("mmdblookup") or os.environ.get("SRP_GEOIP_LOOKUP", "/tmp/srp-geoip-lookup")
        if not os.access(lookup, os.X_OK):
            # The pre-check only confirms the bundled database; the GeoIP cases still assert routing.
            print(f"GeoIP database pre-check skipped: no lookup tool at {lookup}", flush=True)
            lookup = None
        for name, ip, expected in (("geoip-direct-country", self.host, "TR"),
                                   ("geoip-multi-countries", self.host, "TR"),
                                   ("geoip-default-proxy", "192.0.2.1", None)):
            if lookup is None:
                break
            result = subprocess.run([lookup, "--file", str(GEO_DATABASE), "--ip", ip],
                                    capture_output=True, text=True)
            matched = result.returncode == 0 and expected is not None and (
                result.stdout.strip() == expected or f'"{expected}"' in result.stdout)
            if matched != (name != "geoip-default-proxy"):
                raise RuntimeError(f"GeoIP database mismatch for {name}: {result.stdout}")
        listener = self.ssh('ss -ltnp "sport = :28480"')
        match = re.search(r'users:\(\("python3",pid=(\d+)', listener)
        if not match:
            raise RuntimeError("The isolated HTTP reference listener is unavailable")
        command = self.ssh(f"ps -p {int(match[1])} -o args=").strip()
        if command != "python3 /tmp/srp-https-throughput-server.py":
            raise RuntimeError("The reference listener is not the isolated throughput server")

    def ensure_stress_https_server(self):
        parts = urlsplit(self.url)
        try:
            stress_host = socket.gethostbyname(parts.hostname or "")
        except socket.gaierror:
            return
        if parts.scheme != "https" or stress_host != self.host or parts.port != 28483:
            return
        expected = "python3 /tmp/srp-device-matrix/https_health_server.py"
        listener = self.ssh('ss -H -ltnp "sport = :28483"')
        match = re.search(r'pid=(\d+)', listener)
        if match:
            command = self.ssh(f"ps -p {int(match[1])} -o args=").strip()
            if command != expected:
                raise RuntimeError("The isolated HTTPS port belongs to an unrelated process")
            return
        if listener.strip():
            raise RuntimeError("The isolated HTTPS port is occupied by an unrelated listener: " + listener.strip())

        self.ssh("mkdir -p /tmp/srp-device-matrix")
        self.ssh("python3 -c 'from pathlib import Path; "
                 "p=Path(\"/tmp/srp-throughput-public/throughput.bin\"); "
                 "p.parent.mkdir(parents=True, exist_ok=True); "
                 "p.exists() or p.write_bytes(bytes(16 * 1024 * 1024)); "
                 "assert p.stat().st_size == 16 * 1024 * 1024'")
        self.scp("/tmp/srp-https-health-server.py", self.remote_dir + "/https_health_server.py")
        pidfile = self.remote_dir + "/https-health.pid"
        self.ssh(f"nohup {expected} > {self.remote_dir}/https-health.log 2>&1 < /dev/null & echo $! > {pidfile}")
        self.stress_https_started = True
        rules = self.ssh("nft list chain ip filter ufw-user-input")
        if "tcp dport 28483" not in rules:
            self.ssh(f"nft add rule ip filter ufw-user-input {self.firewall_match()}tcp dport 28483 "
                     "counter accept comment SRP_Isolated_Tests")
            self.stress_https_firewall = True
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                self.ssh("curl -k --fail --max-time 5 -o /dev/null "
                         "'https://127.0.0.1:28483/throughput.bin?srp-live=0-0'")
                return
            except RuntimeError:
                time.sleep(0.1)
        raise RuntimeError("The isolated HTTPS server did not complete a real GET request")

    def stop_stress_https_server(self):
        if not self.stress_https_started:
            return
        expected = "python3 /tmp/srp-device-matrix/https_health_server.py"
        pidfile = self.remote_dir + "/https-health.pid"
        self.ssh(f"if [ -f {pidfile} ]; then p=$(read -r pid < {pidfile}; printf '%s' \"$pid\"); "
                 f"if [ \"$(ps -p \"$p\" -o args=)\" = \"{expected}\" ]; then kill -TERM \"$p\"; fi; fi")
        self.stress_https_started = False

    def stop_stress_https_firewall(self):
        if not self.stress_https_firewall:
            return
        rules = self.ssh("nft -a list chain ip filter ufw-user-input")
        for line in rules.splitlines():
            if "SRP_Isolated_Tests" not in line or "tcp dport 28483" not in line:
                continue
            match = re.search(r" handle (\d+)$", line)
            if match:
                self.ssh(f"nft delete rule ip filter ufw-user-input handle {int(match[1])}")
        self.stress_https_firewall = False

    def stop_direct_server(self):
        self.stop_health_server()
        self.stop_stress_https_server()
        self.stop_stress_https_firewall()

    def stop_device_vpn(self):
        env = os.environ.copy()
        env["TEST_RUNNER_SRP_STOP_LIVE_VPN"] = "1"
        command = self.xcode_command(env, "testStopAnyLiveVPNWhenConfigured")
        run_logged(command, self.work / "cleanup-device.log", env=env, timeout=90)

    def xcode_command(self, env, test):
        command = ["xcodebuild", "test", "-workspace", str(self.root / "SRP-VPN-Connect.xcworkspace"),
                   "-scheme", self.scheme, "-configuration", self.configuration, "-destination", f"id={self.device}",
                   "-derivedDataPath", str(self.derived_data),
                   f"-only-testing:SRP-VPN-ConnectTests/SROptionsTests/{test}"]
        key_path = os.environ.get("SRP_TEST_ASC_KEY_PATH")
        if key_path:
            command += ["-allowProvisioningUpdates", "-authenticationKeyPath", key_path,
                        "-authenticationKeyID", os.environ["SRP_TEST_ASC_KEY_ID"],
                        "-authenticationKeyIssuerID", os.environ["SRP_TEST_ASC_ISSUER_ID"]]
        return command + [f"DEVELOPMENT_TEAM={self.team}", "CODE_SIGN_STYLE=Automatic"]

    def run_case(self, item, client_path):
        name = item[0]
        result = {"id": name, "configuration": self.effective_configuration(item),
                  "client_path": str(client_path), "peer_path": str(self.work / f"{name}-peer.json"),
                  "tcp": {}, "udp": {}, "teardown": {}}
        env = self.environment(item, client_path)
        udp = env["TEST_RUNNER_SRP_WW_UDP_STRESS"] == "1"
        if not udp:
            result["udp"] = {"status": "not-applicable", "reason": "The generated connector does not support application UDP"}
        elif os.environ.get("SRP_TEST_WW_FULL_DUPLEX") == "1":
            udp = False
            result["udp"] = {"status": "not-applicable", "reason": "The full-duplex test exercises TCP only"}
        started = time.monotonic()
        try:
            self.start_remote_peer(item, client_path)
            log = self.work / f"{name}-device.log"
            full_duplex = os.environ.get("SRP_TEST_WW_FULL_DUPLEX") == "1"
            network_transition = os.environ.get("SRP_TEST_WW_NETWORK_TRANSITION") == "1"
            test_name = ("testWaterWallLiveNetworkTransitionWhenConfigured" if network_transition else
                         "testWaterWallLiveFullDuplexWhenConfigured" if full_duplex else
                         "testWaterWallLiveConnectionAndThroughputWhenConfigured")
            timeout = self.args.duration * 4 + 1500 if network_transition else self.args.duration + 240
            status = run_logged(self.xcode_command(env, test_name), log, env=env, timeout=timeout)
            text = log.read_text(errors="replace") if log.exists() else ""
            if env["TEST_RUNNER_SRP_WW_TCP_STRESS"] == "0":
                result["tcp"] = {"status": "not-applicable", "reason": "Application protocol is fixed to UDP"}
                result["ping"] = {"status": "not-applicable", "reason": "HTTPS probing is not requested for a fixed UDP application"}
            else:
                ping_samples = [] if network_transition else [float(value) for value in re.findall(r"Live HTTPS 204: Ping: ([0-9.]+) ms", text)]
                ping_passed = status == 0 and len(ping_samples) >= 2
                ping_status = ("not-applicable" if network_transition else
                               "passed" if ping_passed else "failed" if not ping_samples or status == 0 else "not-completed")
                result["ping"] = {"status": ping_status, "samples_ms": ping_samples}
                if network_transition:
                    matches = list(re.finditer(r"Sustained stress: ([0-9.]+) seconds, (\d+) bytes, (\d+) requests, errors: \(\s*\), VPN status: \d+, finished: (\d+)/(\d+), timeouts: (\d+)", text))
                    passed = (status == 0 and len(matches) >= 4 and "TEST SUCCEEDED" in text and
                              all(float(match[1]) >= self.args.duration and match[2] != "0" and
                                  match[4] == match[5] and match[6] == "0" for match in matches))
                    result["tcp"] = {"status": "passed" if passed else "failed",
                                      "phases": len(matches),
                                      "duration_s": sum(float(match[1]) for match in matches) if matches else round(time.monotonic() - started, 3),
                                      "bytes": sum(int(match[2]) for match in matches),
                                      "requests": sum(int(match[3]) for match in matches),
                                      "timeouts": sum(int(match[6]) for match in matches) if matches else None,
                                      "error": "" if passed else tail(log)}
                elif full_duplex:
                    match = re.search(r"Sustained full-duplex: ([0-9.]+) seconds, downloaded=(\d+), uploaded=(\d+), download_requests=(\d+), upload_requests=(\d+), errors=\(\s*\), finished=(\d+)/(\d+), timeouts=(\d+)(?:, VPN status=-?\d+)?", text)
                    passed = (status == 0 and match is not None and float(match[1]) >= self.args.duration and
                              match[2] != "0" and match[3] != "0" and match[6] == match[7] and
                              match[8] == "0" and "TEST SUCCEEDED" in text)
                    result["tcp"] = {"status": "passed" if passed else "failed",
                                      "duration_s": float(match[1]) if match else round(time.monotonic() - started, 3),
                                      "bytes": int(match[2]) if match else 0,
                                      "upload_bytes": int(match[3]) if match else 0,
                                      "requests": int(match[4]) + int(match[5]) if match else 0,
                                      "timeouts": int(match[8]) if match else None,
                                      "error": "" if passed else tail(log)}
                else:
                    match = re.search(r"Sustained stress: ([0-9.]+) seconds, (\d+) bytes, (\d+) requests, errors: \(\s*\), VPN status: \d+, finished: (\d+)/(\d+), timeouts: (\d+)", text)
                    passed = (status == 0 and match is not None and float(match[1]) >= self.args.duration and
                              match[2] != "0" and match[4] == match[5] and match[6] == "0" and
                              "Live stress finished" in text and "TEST SUCCEEDED" in text)
                    result["tcp"] = {"status": "passed" if passed else "failed",
                                      "duration_s": float(match[1]) if match else round(time.monotonic() - started, 3),
                                      "bytes": int(match[2]) if match else 0,
                                      "requests": int(match[3]) if match else 0,
                                      "timeouts": int(match[6]) if match else None,
                                      "error": "" if passed else tail(log)}
            if udp:
                udp_match = re.search(r"Sustained UDP: ([0-9.]+) seconds, sent=(\d+), received=(\d+), errors=(\d+), timeouts=(\d+), passed=([01])", text)
                udp_passed = udp_match is not None and udp_match[6] == "1"
                timing = re.search(r"Sustained UDP: .*rtt_ms=([0-9.]+), jitter_ms=([0-9.]+), max_rtt_ms=([0-9.]+)", text)
                result["udp"] = {"status": "passed" if udp_passed else "failed",
                                  "duration_s": float(udp_match[1]) if udp_match else 0,
                                  "sent": int(udp_match[2]) if udp_match else 0,
                                  "received": int(udp_match[3]) if udp_match else 0,
                                  "timeouts": int(udp_match[5]) if udp_match else None,
                                  "average_rtt_ms": float(timing[1]) if timing else None,
                                  "average_jitter_ms": float(timing[2]) if timing else None,
                                  "max_rtt_ms": float(timing[3]) if timing else None,
                                  "error": "" if udp_passed else "UDP transfer failed; see device log"}
            self.stop_remote_peer(item)
            result["teardown"] = {"passed": True}
        except Exception as error:
            result["error"] = str(error)
            result["teardown"] = {"passed": False, "error": str(error)}
        finally:
            try:
                self.stop_device_vpn()
            except Exception as error:
                result["teardown"] = {"passed": False, "error": str(error)}
            try:
                self.stop_remote_peer(item)
            except Exception as error:
                result["teardown"] = {"passed": False, "error": str(error)}
        result["status"] = "failed" if (result.get("error") or result["tcp"].get("status") == "failed" or
            result["udp"].get("status") == "failed" or result.get("ping", {}).get("status") == "failed" or
            not result["teardown"].get("passed", False)) else "passed"
        self.results.append(result)
        write_json(self.work / "results.json", {"summary": self.summary, "cases": self.results})
        print(f"{name}: {result['status']} TCP={result['tcp']} UDP={result['udp']} "
              f"ping={result.get('ping', {})} teardown={result['teardown']}", flush=True)
        return result

    def run(self):
        if not self.host or not self.binary or not self.url:
            raise RuntimeError("SRP_TEST_SSH_HOST, SRP_TEST_PEER_BINARY and SRP_TEST_HTTP_URL are required")
        selected = list(candidate_specs())
        if self.args.only:
            allowed = set(self.args.only.split(","))
            selected = [item for item in selected if item[0] in allowed or item[1] in allowed or item[10] in allowed]
        candidate_total = len(selected)
        start = self.args.case_start
        selected = selected[start:start + self.args.case_limit if self.args.case_limit is not None else None]
        if not selected:
            raise ValueError("No matching test cases")
        self.args.port = 4097
        self.args.cover_port = 4098
        native_build_log = self.work / "native-build.log"
        if run_logged(["cmake", "--build", str(self.root / "WaterWall/build/ios"),
                       "--target", "SRPWaterWallRuntime", "--config", self.configuration, "-j2"],
                      native_build_log, timeout=600) != 0:
            raise RuntimeError(tail(native_build_log))
        clients = self.prepare_clients(selected)
        self.summary.update({"candidate_total": candidate_total, "range_start": start,
                             "range_count": len(selected)})
        if self.args.enumerate_only:
            return 0
        if any(item[2] in ("tls", "quic", "reality") for item in selected if item[0] in clients):
            if run_logged([os.environ.get("SRP_MATRIX_OPENSSL", "openssl"), "req", "-x509",
                           "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                           "-addext", "subjectAltName=DNS:localhost", "-keyout", str(self.key),
                           "-out", str(self.cert), "-days", "1"], self.work / "certificate.log", timeout=30) != 0:
                raise RuntimeError(tail(self.work / "certificate.log"))
        try:
            self.prepare_remote_peer()
            self.ensure_stress_https_server()
            if any(item[0].startswith("geoip-") for item in selected if item[0] in clients):
                self.start_direct_server()
            self.ensure_udp_server()
            for item in selected:
                if item[0] in clients:
                    self.record_result(self.run_isolated_case(item, clients[item[0]]))
        finally:
            self.stop_udp_server()
            self.stop_remote_peer()
            self.stop_direct_server()
            self.stop_remote_firewall()
        failures = self.summarize_results()
        write_json(self.work / "results.json", {"summary": self.summary, "cases": self.results})
        print(f"Completed: {self.summary}", flush=True)
        return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description="Run validator-generated WaterWall combinations through a real iPhone Network Extension")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--only")
    parser.add_argument("--enumerate-only", action="store_true")
    parser.add_argument("--duration", type=int, default=90)
    parser.add_argument("--wireguard-only", action="store_true")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--case-start", type=int, default=0, help="Zero-based index in the filtered candidate list")
    parser.add_argument("--case-limit", type=int, help="Maximum number of candidates in this run")
    args = parser.parse_args()
    if args.case_start < 0 or (args.case_limit is not None and args.case_limit < 1):
        parser.error("case-start must be nonnegative and case-limit must be positive")
    if args.duration < 90 or args.duration > 3600:
        parser.error("Device acceptance requires at least 90 seconds per case")
    if args.rounds < 1 or args.rounds > 10:
        parser.error("Rounds must be between 1 and 10")
    try:
        return DeviceMatrix(args).run()
    except Exception as error:
        print(f"Device matrix setup failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
