#!/usr/bin/env python3
"""Turns a WaterWall device test run into the documentation's scenario pages.

  extract  reads a device_matrix.py work folder and writes a sanitized evidence file
  render   writes waterwall/scenarios/*.html and the scenario part of nav.js from evidence files

Only the evidence files are kept in the repository; the work folders live in macOS temp.
"""
import argparse
import html
import json
import re
import sys
from pathlib import Path

SITE = Path(__file__).resolve().parent.parent
UUID_FIXTURE = "00112233-4455-6677-8899-aabbccddeeff"
OUTER_FIXTURE = "matrix-only-placeholder"
STAMP = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)")
PUBLIC_IPV4 = re.compile(r"\b(?!(?:10|127|0)\.)(?!192\.168\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)(?!100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)"
                         r"(?!198\.1[89]\.)(?!255\.)(?!192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)"  # RFC 5737 examples
                         r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
# Paths on the Mac that ran the tests, such as xcodebuild's result bundles; the server's own test folder stays
LOCAL_PATH = re.compile(r"(?:/private)?(?:/tmp/(?!srp-device-matrix/)|/var/folders/|/Users/)[^\s\"']*")


class Sanitizer:
    def __init__(self, replacements):
        self.replacements = [(old, new) for old, new in replacements if old]

    def text(self, value):
        value = value.replace(str(SITE.parent) + "/", "")
        for old, new in self.replacements:
            value = value.replace(old, new)
        value = LOCAL_PATH.sub("<LOCAL_PATH>", value)
        value = value.replace(UUID_FIXTURE, "<UUID>").replace(OUTER_FIXTURE, "<OUTER_PASSWORD>")
        value = re.sub(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "<UUID>", value)
        return value

    def data(self, value, key=""):
        if isinstance(value, dict):
            return {k: self.data(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [self.data(v, key) for v in value]
        if isinstance(value, str):
            if key in ("private-key", "privatekey", "preshared-key", "public-key", "peer-public-key"):
                return "<" + key.upper().replace("-", "_") + ">"
            return self.text(value)
        return value


def block_after(lines, index, opener, closer):
    """The line at index plus the following lines up to the one that closes what it opened."""
    block = [lines[index].strip()]
    if lines[index].rstrip().endswith(opener) or (opener + " " in lines[index] and closer not in lines[index].split(opener, 1)[1]):
        for follow in lines[index + 1:index + 60]:
            block.append(follow.strip())
            if follow.strip().startswith(closer):
                break
    return " ".join(block)


def measured(sustained):
    """The numbers of a 'Sustained <mode>: N seconds, key=value, …' or 'Sustained stress: …' line."""
    stress = re.search(r"Sustained stress: ([\d.]+) seconds, (\d+) bytes, (\d+) requests, errors: \((.*?)\), "
                       r"VPN status: (\d+), finished: (\d+/\d+), timeouts: (\d+)", sustained)
    if stress:
        return {"mode": "download", "seconds": float(stress.group(1)), "downloaded": int(stress.group(2)), "uploaded": 0,
                "download_requests": int(stress.group(3)), "errors": re.findall(r'"([^"]*)"', stress.group(4)),
                "finished": stress.group(6), "timeouts": int(stress.group(7))}
    match = re.search(r"Sustained ([a-z -]+): ([\d.]+) seconds, (.*)", sustained)
    if not match:
        return None
    values = {"mode": match.group(1), "seconds": float(match.group(2))}
    rest = match.group(3)
    errors = re.search(r"errors=\((.*?)\)", rest)
    values["errors"] = re.findall(r'"([^"]*)"', errors.group(1)) if errors else []
    for key, value in re.findall(r"([a-z_ ]+?)=([^,()]+)", re.sub(r"errors=\(.*?\)", "", rest)):
        key = key.strip().replace(" ", "_")
        values[key] = int(value) if value.strip().isdigit() else value.strip()
    return values


def device_details(log_path, sanitize):
    """The lines of a device log that describe the run, with secrets and addresses removed."""
    if not log_path.exists():
        return {}
    lines = log_path.read_text(errors="replace").splitlines()
    stamps = [m.group(1) for m in map(STAMP.match, lines) if m]
    details = {"started": stamps[0] if stamps else None, "finished": stamps[-1] if stamps else None,
               "sustained": None, "measured": None, "phases": [], "udp_phases": [], "https_checks": [], "failures": [],
               "last_error": None}
    for index, line in enumerate(lines):
        if "] Sustained UDP:" in line:
            details["udp"] = sanitize.text(line.split("] ", 1)[-1])
            details["udp_phases"].append(details["udp"])
        elif "Sustained " in line and " seconds" in line and "] Sustained" in line:
            text = block_after(lines, index, "(", ")").split("] ", 1)[-1]
            details["sustained"] = sanitize.text(text)
            details["measured"] = measured(details["sustained"])
            if details["measured"]:
                details["phases"].append(details["measured"])
        elif "Live HTTPS 204:" in line:
            details["https_checks"].append(line.split("Live HTTPS 204:", 1)[1].strip())
        elif ": error: -[SROptionsTests" in line:
            details["failures"].append(sanitize.text(line.split(": error: ", 1)[1].strip()))
        elif "WaterWall last error:" in line:
            details["last_error"] = sanitize.text(block_after(lines, index, "{", "}").split("WaterWall last error:", 1)[1].strip())
    return details


def extract(args):
    work = Path(args.work)
    secrets = Path(args.secrets_file).read_text().split() if args.secrets_file else []
    sanitize = Sanitizer([(secret, "<PASSWORD>") for secret in secrets] +
                         [(args.server_ip, "<SERVER_IP>"), (args.client_ip, "<CLIENT_IP>"),
                          (args.server_host, "<SERVER_HOST>"), (args.device_id, "<DEVICE_ID>")])
    provenance = {}
    for line in Path(args.provenance).read_text().splitlines():
        if "=" in line and not line.startswith(("ids=", " ", "?")):
            key, value = line.split("=", 1)
            provenance[key] = value
    why = {}
    if args.selection:
        why = {case["id"]: case.get("why", "") for case in json.loads(Path(args.selection).read_text())["selected"]}
    results = json.loads((work / "results.json").read_text())
    cases = []
    for case in results["cases"]:
        for round_ in case.get("rounds", [])[:1]:
            folder = work / case["id"] / f"round-{round_.get('round', 1)}"
            # Lifecycle steps sit in the round; the chain itself is documented by the matrix run.
            for step in round_.get("lifecycle", []):
                cases.append({
                    "id": f"lifecycle-{step['step']}-{case['id']}",
                    "kind": "lifecycle",
                    "step": step["step"],
                    "chain_case": case["id"],
                    "configuration": case.get("configuration"),
                    "client": None,
                    "server": {},
                    "result": sanitize.data({"status": step["status"], "duration_s": step.get("duration_s"),
                                             "error": (step.get("error") or "")[-1500:]}),
                    "device": device_details(folder / f"{case['id']}-{step['step']}.log", sanitize),
                })
            if args.kind == "lifecycle":
                continue
            def load(name):
                path = folder / f"{case['id']}-{name}.json"
                return sanitize.data(json.loads(path.read_text())) if path.exists() else None
            client = Path(case.get("client_path", ""))
            entry = {
                "id": case["id"] + args.id_suffix,
                "kind": args.kind,
                "why": why.get(case["id"]) or case.get("why", ""),
                "sni": case.get("sni"),
                "server_file": case.get("server_file"),
                "configuration": case.get("configuration"),
                "client": sanitize.data(json.loads(client.read_text())) if client.is_file() else None,
                "server": {"peer": load("peer"), "core": load("core"), "cover": load("cover")},
                "result": sanitize.data({k: round_.get(k) for k in ("status", "tcp", "udp", "ping", "teardown", "lifecycle")}),
                "device": device_details(folder / f"{case['id']}-device.log", sanitize),
            }
            if entry["result"].get("tcp", {}) and entry["result"]["tcp"].get("error"):
                entry["result"]["tcp"]["error"] = entry["result"]["tcp"]["error"][-1500:]
            cases.append(entry)
    evidence = {
        "run": {k: provenance.get(k) for k in ("start_utc", "end_utc", "head", "peer_sha256", "exit")},
        "summary": results.get("summary"),
        "environment": json.loads(args.environment) if args.environment else {},
        "cases": cases,
    }
    text = json.dumps(evidence, indent=1, sort_keys=False)
    leaks = sorted(set(PUBLIC_IPV4.findall(text)))
    if leaks:
        sys.exit("Refusing to write: public IPv4 addresses remain: " + ", ".join(leaks))
    local = LOCAL_PATH.search(text)
    if local:
        sys.exit("Refusing to write: a local path remains: " + local.group(0))
    Path(args.output).write_text(text + "\n")
    print(f"{len(cases)} cases -> {args.output}")


# ---------------------------------------------------------------- render

APPS = {"vless": "VLESS", "vmess": "VMess", "trojan": "Trojan", "socks5": "SOCKS5", "http-proxy": "HTTP CONNECT"}
OUTERS = {"tls": "TLS", "reality": "Reality", "aead": "AEAD", "bgp4": "BGP4"}
GROUPS = [("production", "Production server"), ("tls", "TLS"), ("reality", "Reality"), ("aead", "AEAD"), ("quic", "QUIC"),
          ("none", "No outer layer"), ("bgp4", "BGP4"), ("raw", "Raw IPv4"), ("modes", "Direct and WireGuard"),
          ("advanced", "Advanced settings"), ("download", "UDP and GeoIP routing"), ("lifecycle", "Connection lifecycle")]
LABELS = {"verified": "VERIFIED — TESTED SUCCESSFULLY", "failed": "TESTED — FAILED",
          "partial": "TESTED — PARTIALLY WORKING", "not-verified": "NOT VERIFIED"}


def e(value):
    return html.escape(str(value), quote=True)


def title_of(case):
    if case.get("title"):
        return case["title"]
    c = case.get("configuration") or {}
    if case["id"].startswith("direct-diagnostics") or c.get("mode") == "direct":
        return "Direct mode (diagnostics)" + suffix_of(case)
    if case["id"].startswith("wireguard-native") or c.get("mode") == "wireguard":
        return "WireGuard mode" + suffix_of(case)
    parts = ["Raw IPv4"] if c.get("input") == "raw-ipv4" else [APPS.get(c.get("application"), c.get("application", "?"))]
    if c.get("mux"):
        parts.append("MUX")
    if c.get("obfuscator"):
        parts.append("Obfuscator")
    if c.get("http") == "websocket":
        parts.append("WebSocket" + (" (HTTP/2)" if c.get("http-version") == 2 else ""))
    elif c.get("http") == "http":
        parts.append("HTTP/2" if c.get("http-version") == 2 else "HTTP/1.1")
    if c.get("bgp4") and c.get("outer") != "bgp4":
        parts.append("BGP4 framing")
    outer = c.get("outer")
    if outer == "quic":
        parts.append("QUIC " + ("Stream" if c.get("quic-carrier") == "stream" else "Datagram"))
    elif outer in OUTERS:
        parts.append(OUTERS[outer])
    if c.get("carrier") == "kcp":
        parts.append("KCP")
    title = " + ".join(parts)
    if outer == "none" and len(parts) == 1:
        title += " (no outer layer)"
    options = c.get("node-options") or {}
    if case["id"].startswith("adv-") and options:
        settings = ", ".join(f"{layer} {key} = {json.dumps(value)}" for layer, values in options.items()
                             for key, value in values.items())
        title += f" with {settings}"
    countries = (c.get("geoip") or {}).get("countries") or (["IR"] if (c.get("geoip") or {}).get("iran-direct") else [])
    if countries:
        title += " with GeoIP direct routing for " + ", ".join(countries)
    return title + suffix_of(case)


def suffix_of(case):
    if case.get("kind") == "production" and case.get("server_file"):
        return f" ({case['server_file']}{', SNI typed' if case.get('sni') else ''})"
    if case.get("kind") == "download" and not case["id"].startswith("geoip-"):
        return " (downloads and UDP)"
    return ""


def group_of(case):
    if case["kind"] in ("lifecycle", "production", "download"):
        return case["kind"]
    if case["id"].startswith("adv-") or case["id"].startswith("geoip-"):
        return "advanced"
    c = case.get("configuration") or {}
    if c.get("mode") in ("direct", "wireguard") or case["id"] in ("direct-diagnostics", "wireguard-native"):
        return "modes"
    if c.get("input") == "raw-ipv4":
        return "raw"
    return c.get("outer", "none")


def traffic_of(case):
    """Seconds, downloaded and uploaded bytes: the test log's numbers, which failed runs keep too."""
    numbers = (case.get("device") or {}).get("measured") or {}
    tcp = case["result"].get("tcp") or {}
    if numbers:
        return numbers.get("seconds") or 0, numbers.get("downloaded") or 0, numbers.get("uploaded") or 0
    return tcp.get("duration_s") or 0, tcp.get("bytes") or 0, tcp.get("upload_bytes") or 0


def status_of(case):
    if case["result"].get("status") == "passed":
        return "verified"
    _, down, up = traffic_of(case)
    moved = down > 0 if case["kind"] == "download" else down > 0 and up > 0
    return "partial" if moved else "failed"


def megabytes(value):
    return f"{(value or 0) / 1e6:,.0f} MB"


def rate(value, seconds):
    return f"{(value or 0) * 8 / 1e6 / seconds:,.0f} Mbit/s" if seconds else "—"


PURPOSE = {
    "tls": "TLS wraps the connection in the same encryption HTTPS uses, so it looks like ordinary web traffic.",
    "reality": "Reality makes the connection start like a visit to another TLS website, so the server needs no certificate of its own.",
    "aead": "AEAD encrypts the connection with a shared password and has no TLS handshake.",
    "quic": "QUIC carries the connection in encrypted QUIC.",
    "none": "There is no outer layer: the application protocol goes over the network as it is.",
    "bgp4": "BGP4 framing makes the stream look like BGP routing messages. It does not encrypt.",
    "raw": "Raw IPv4 sends whole IP packets as one stream instead of separate connections.",
}


def purpose_of(case):
    c = case.get("configuration") or {}
    group = group_of(case)
    if case["id"].startswith("geoip-"):
        return ("GeoIP routing sends traffic for the countries you choose straight to the internet and everything else "
                "through the server. This case checks which way the downloads from our server, which is in Turkey (TR), went.")
    if case["id"].startswith("direct-diagnostics"):
        return "Direct mode sends the phone's traffic straight to the internet through the app's WaterWall, with no server. It checks the phone side alone."
    if case["id"].startswith("wireguard-native") or (c.get("mode") == "wireguard" and case["kind"] == "production"):
        return "WireGuard mode connects the app's WireGuard client to a WireGuard server run by WaterWall."
    if group == "advanced" or (group == "download" and case["id"].startswith("adv-")):
        return "This case keeps a normal chain and changes one advanced node setting, to check that the setting works."
    text = PURPOSE.get("raw" if c.get("input") == "raw-ipv4" else c.get("outer", "none"), "")
    extras = []
    if c.get("mux"):
        extras.append("MUX carries many connections inside one")
    if c.get("http") == "websocket":
        extras.append("a WebSocket layer makes it look like a web socket connection")
    elif c.get("http") == "http":
        extras.append("an HTTP layer makes it look like web requests")
    if c.get("obfuscator"):
        extras.append("the XOR obfuscator scrambles the bytes")
    if c.get("carrier") == "kcp":
        extras.append("KCP carries it over UDP")
    if extras:
        text += " In this case " + ", ".join(extras) + "."
    return text


def code(label, value):
    body = value if isinstance(value, str) else json.dumps(value, indent=2)
    language = "json" if not isinstance(value, str) else "bash"
    return f'<pre data-label="{e(label)}"><code class="language-{language}">{e(body)}</code></pre>'


def settings_rows(case):
    c = case.get("configuration") or {}
    rows = [("Mode", {"chain": "Chain", "direct": "Direct", "wireguard": "WireGuard"}.get(c.get("mode"), c.get("mode")))]
    if c.get("mode", "chain") == "chain":
        rows.append(("Input", "Raw IPv4" if c.get("input") == "raw-ipv4" else "Connections"))
        if c.get("input") != "raw-ipv4":
            rows.append(("Application", APPS.get(c.get("application"), c.get("application"))))
            rows.append(("MUX", "On" if c.get("mux") else "Off"))
        rows.append(("Obfuscator", "On" if c.get("obfuscator") else "Off"))
        rows.append(("HTTP", {"off": "Off", "http": "HTTP", "websocket": "WebSocket"}.get(c.get("http"), c.get("http"))))
        if c.get("http") != "off":
            rows.append(("HTTP Version", str(c.get("http-version", 1))))
        rows.append(("BGP4 Framing", "On" if c.get("bgp4") or c.get("outer") == "bgp4" else "Off"))
        outer = c.get("outer")
        rows.append(("Outer", "QUIC" if outer == "quic" else OUTERS.get(outer, "None")))
        if outer == "quic":
            rows.append(("QUIC Carrier", "Stream" if c.get("quic-carrier") == "stream" else "Datagram"))
        else:
            rows.append(("Carrier", "KCP" if c.get("carrier") == "kcp" else "TCP"))
    return rows


def setup_of(env, run):
    """The shared setup rows, with {head} replaced by the commit the run tested."""
    return [(k, v.replace("{head}", (run.get("head") or "")[:8])) for k, v in env.get("setup", [])]


def render_case(case, env, run):
    status = status_of(case)
    result = case["result"]
    device = case.get("device") or {}
    numbers = device.get("measured") or {}
    title = title_of(case)
    seconds, down, up = traffic_of(case)
    out = [f"<h1>{e(title)}</h1>", f'<p class="lead">{e(purpose_of(case))}</p>',
           f'<p><span class="status {status}">{LABELS[status]}</span> &nbsp;Tested {e(env.get("date_text", ""))} on the current app build against WaterWall {e(env.get("server_version", ""))}.</p>']

    out.append("<h2>Result</h2>")
    rows = [("Outcome", "Passed: every check succeeded." if status == "verified" else
             "Failed: traffic moved, but not every check succeeded." if status == "partial" else "Failed.")]
    if seconds:
        rows += [("Test length", f"{seconds:.0f} seconds"),
                 ("Downloaded", f"{megabytes(down)} ({rate(down, seconds)} on average)")]
        if case["kind"] != "download":
            rows.append(("Uploaded", f"{megabytes(up)} ({rate(up, seconds)} on average)"))
    if numbers:
        uploads = "" if case["kind"] == "download" else f" and {numbers.get('upload_requests', '—')} uploads"
        rows.append(("Transfers", f"{numbers.get('download_requests', '—')} downloads{uploads} of 16 MiB; "
                                  f"{numbers.get('finished', '—')} streams finished at the end"))
        rows.append(("Errors", "; ".join(numbers.get("errors") or []) or "none"))
        rows.append(("Timeouts", str(numbers.get("timeouts", "—"))))
    routing = result.get("routing") or {}
    if routing:
        expected = "straight from the phone" if routing.get("expected") == "direct" else "through WaterWall"
        rows.append(("GeoIP routing", f"{routing.get('status', '—')}: expected {expected}; the reference server saw "
                                      f"{routing.get('direct_requests', 0)} downloads from the phone's own address and "
                                      f"{routing.get('proxied_requests', 0)} through WaterWall"))
    if device.get("https_checks"):
        rows.append(("HTTPS check through the tunnel", "; ".join(device["https_checks"])))
    udp = result.get("udp") or {}
    if udp.get("sent") is not None:
        rows.append(("UDP", f"{udp.get('status')}: {udp.get('sent')} datagrams sent and {udp.get('received')} echoed back in "
                            f"{udp.get('duration_s', 0):.0f} seconds; round trip {udp.get('average_rtt_ms') or 0:.0f} ms on average, "
                            f"{udp.get('max_rtt_ms') or 0:.0f} ms at most"))
    elif udp:
        rows.append(("UDP", udp.get("status", "—") + (f": {udp['reason']}" if udp.get("reason") else "")))
    out.append("<table><tbody>" + "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in rows) + "</tbody></table>")
    if status != "verified":
        problems = device.get("failures", []) + ([device["last_error"]] if device.get("last_error") else [])
        if device.get("sustained"):
            problems.insert(0, device["sustained"])
        if problems:
            out.append("<h3>What the test reported</h3>")
            out.append(code("Lines from the test log", "\n".join(problems)))

    out.append("<h2>Test setup</h2>")
    out.append("<table><tbody>" + "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in setup_of(env, run)) + "</tbody></table>")
    out.append(f'<pre data-label="Illustration — not a capture of a real network"><code>{e(env.get("topology", ""))}</code></pre>')

    out.append("<h2>Server configuration</h2>")
    out.append(f"<p>{e(env.get('server_intro', ''))}</p>")
    server = case.get("server") or {}
    if server.get("peer"):
        out.append(code("Server chain (peer.json)", server["peer"]))
    if server.get("cover"):
        out.append("<p>The Reality cover site in this test was a second TLS server on the same machine:</p>")
        out.append(code("Cover site (cover.json)", server["cover"]))
    if server.get("core"):
        out.append("<details><summary>The test copy's core.json</summary>" + code("core.json", server["core"]) + "</details>")

    out.append("<h2>App settings</h2>")
    out.append("<p>On the <a href=\"../ui-guide.html#configuration-screen\">WaterWall configuration screen</a>:</p>")
    out.append("<table><thead><tr><th>Row</th><th>Value</th></tr></thead><tbody>" +
               "".join(f"<tr><td><strong>{e(k)}</strong></td><td>{e(v)}</td></tr>" for k, v in settings_rows(case)) + "</tbody></table>")
    options = (case.get("configuration") or {}).get("node-options") or {}
    if options:
        out.append("<p>Advanced node settings used in this case:</p>")
        out.append(code("ADVANCED NODE SETTINGS", options))
    out.append("<p>In the profile editor:</p>")
    profile = env.get("profile", [])
    if case["kind"] == "production":
        sni = case.get("sni") or "Empty, so the app sends the Server field (<SERVER_HOST>)"
        profile = [(k, sni if k == "SNI (optional)" else v) for k, v in profile]
    out.append("<table><tbody>" + "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in profile) + "</tbody></table>")
    if case.get("client"):
        out.append("<details><summary>The client chain the app built (for reference)</summary>" +
                   code("Client chain", case["client"]) + "</details>")

    out.append("<h2>How it was tested</h2>")
    out.append(env.get("procedure", ""))

    out.append("<h2>Gaps and limits</h2>")
    out.append("<ul>" + "".join(f"<li>{e(g)}</li>" for g in env.get("gaps", [])) + "</ul>")

    out.append("<h2>Evidence</h2>")
    evidence = [("Test case", e(case["id"])), ("Run", e(f"{run.get('start_utc', '')} to {run.get('end_utc', '')} (UTC)")),
                ("Case log times", e(f"{device.get('started') or '—'} to {device.get('finished') or '—'} (phone time, UTC+3)")),
                ("App source", e(f"commit {(run.get('head') or '')[:8]}")),
                ("Server program", e(f"official WaterWall release, SHA-256 {(run.get('peer_sha256') or '')[:16]}…")),
                ("Evidence file", f'<a href="../../evidence/{e(env["evidence_file"])}">{e(env["evidence_file"])}</a>')]
    if case.get("why"):
        evidence.insert(1, ("Why it was selected", e(case["why"])))
    out.append("<table><tbody>" + "".join(f"<tr><th>{e(k)}</th><td>{v}</td></tr>" for k, v in evidence) + "</tbody></table>")
    return "\n".join(out)


def render_lifecycle(case, env, run):
    step = env["steps"][case["step"]]
    status = status_of(case)
    device = case.get("device") or {}
    duration = case["result"].get("duration_s") or 0
    out = [f"<h1>{e(step['title'])}</h1>", f'<p class="lead">{e(step["purpose"])}</p>',
           f'<p><span class="status {status}">{LABELS[status]}</span> &nbsp;Tested {e(env.get("date_text", ""))} on the current app build against WaterWall {e(env.get("server_version", ""))}.</p>',
           "<h2>Result</h2>"]
    rows = [("Outcome", "Passed: every check succeeded." if status == "verified" else "Failed."),
            ("Test length", f"{duration:.0f} seconds, including connecting and disconnecting")]
    if device.get("https_checks"):
        rows.append(("HTTPS checks through the tunnel", "; ".join(device["https_checks"])))
    for number, phase in enumerate(device.get("phases") or [], 1):
        rows.append((f"Download phase {number}", f"{megabytes(phase.get('downloaded'))} in {phase.get('seconds', 0):.0f} seconds "
                                                 f"({rate(phase.get('downloaded'), phase.get('seconds'))}); "
                                                 f"errors: {'; '.join(phase.get('errors') or []) or 'none'}"))
    for number, line in enumerate(device.get("udp_phases") or [], 1):
        rows.append((f"UDP phase {number}", line))
    out.append("<table><tbody>" + "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in rows) + "</tbody></table>")
    if status != "verified":
        problems = device.get("failures", []) + ([device["last_error"]] if device.get("last_error") else [])
        if problems:
            out.append("<h3>What the test reported</h3>" + code("Lines from the test log", "\n".join(problems)))
    out.append("<h2>What the test does</h2>")
    out.append("<ol>" + "".join(f"<li>{e(item)}</li>" for item in step["procedure"]) + "</ol>")
    out.append(f"<p>{e(step['pass'])}</p>")
    out.append("<h2>Test setup</h2>")
    chain = case.get("chain_case", "")
    out.append(f'<p>The profile used the chain of the <a href="{e(chain)}.html">{e(title_of({"id": chain, "kind": "matrix", "configuration": case.get("configuration")}))}</a> '
               "scenario, with the same server copy and profile settings, except the options the steps above change.</p>")
    out.append("<table><tbody>" + "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in setup_of(env, run)) + "</tbody></table>")
    out.append("<h2>Gaps and limits</h2>")
    out.append("<ul>" + "".join(f"<li>{e(g)}</li>" for g in env.get("gaps", []) + step.get("gaps", [])) + "</ul>")
    out.append("<h2>Evidence</h2>")
    evidence = [("Test case", e(case["id"])), ("Run", e(f"{run.get('start_utc', '')} to {run.get('end_utc', '')} (UTC)")),
                ("Step log times", e(f"{device.get('started') or '—'} to {device.get('finished') or '—'} (phone time, UTC+3)")),
                ("App source", e(f"commit {(run.get('head') or '')[:8]}, Debug build")),
                ("Server program", e(f"official WaterWall release, SHA-256 {(run.get('peer_sha256') or '')[:16]}…")),
                ("Evidence file", f'<a href="../../evidence/{e(env["evidence_file"])}">{e(env["evidence_file"])}</a>')]
    out.append("<table><tbody>" + "".join(f"<tr><th>{e(k)}</th><td>{v}</td></tr>" for k, v in evidence) + "</tbody></table>")
    return "\n".join(out)


def page(title, description, body, depth):
    up = "../" * depth
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)} — WaterWall Scenarios — SRP VPN Connect Documentation</title>
<meta name="description" content="{e(description)}">
<link rel="stylesheet" href="{up}assets/css/site.css">
<script>try{{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}}catch(e){{}}</script>
</head>
<body>
<main>
{body}
</main>
<script src="{up}assets/js/nav.js"></script>
<script src="{up}assets/js/site.js"></script>
</body>
</html>
"""


def render(args):
    out_dir = SITE / "waterwall" / "scenarios"
    out_dir.mkdir(parents=True, exist_ok=True)
    groups = {key: [] for key, _ in GROUPS}
    for evidence_path in args.evidence:
        evidence = json.loads(Path(evidence_path).read_text())
        env = json.loads(Path(args.environment).read_text())[evidence["environment"]["profile"]]
        env["evidence_file"] = Path(evidence_path).name
        env["head"] = (evidence["run"].get("head") or "")[:8]
        env["date"] = (evidence["run"].get("start_utc") or "")[:10]
        for case in evidence["cases"]:
            if case["kind"] == "lifecycle":
                step = env["steps"][case["step"]]
                case["title"] = step["title"]
                body = render_lifecycle(case, env, evidence["run"])
                (out_dir / f"{case['id']}.html").write_text(page(step["title"], step["purpose"], body, 2))
            else:
                body = render_case(case, env, evidence["run"])
                (out_dir / f"{case['id']}.html").write_text(page(title_of(case), purpose_of(case), body, 2))
            groups[group_of(case)].append((case, env))
    # Overview page
    rows = []
    totals = {"verified": 0, "partial": 0, "failed": 0}
    for key, name in GROUPS:
        if not groups[key]:
            continue
        rows.append(f'<h2 id="{key}">{e(name)}</h2><table><thead><tr><th>Scenario</th><th>Status</th><th>Down / up</th></tr></thead><tbody>')
        for case, env in sorted(groups[key], key=lambda item: title_of(item[0])):
            status = status_of(case)
            totals[status] += 1
            seconds, down, up = traffic_of(case)
            speed = f"{rate(down, seconds)} / {rate(up, seconds)}" if seconds else "—"
            rows.append(f'<tr><td><a href="{e(case["id"])}.html">{e(title_of(case))}</a></td>'
                        f'<td><span class="status {status}">{LABELS[status]}</span></td><td>{e(speed)}</td></tr>')
        rows.append("</tbody></table>")
    intro = Path(args.intro).read_text() if args.intro else ""
    summary = (f"<p><strong>{sum(totals.values())}</strong> scenarios: {totals['verified']} verified, "
               f"{totals['partial']} partially working, {totals['failed']} failed.</p>")
    (out_dir / "index.html").write_text(page("Verified Test Scenarios", "Every WaterWall scenario we tested, with its result.",
                                             "<h1>Verified Test Scenarios</h1>\n" + intro + summary + "\n".join(rows), 2))
    # Scenario part of the navigation
    nav_items = [{"title": "Overview", "href": "waterwall/scenarios/index.html"}]
    for key, name in GROUPS:
        if groups[key]:
            nav_items.append({"title": name, "children": [{"title": title_of(case), "href": f"waterwall/scenarios/{case['id']}.html"}
                                                           for case, _ in sorted(groups[key], key=lambda item: title_of(item[0]))]})
    nav_path = SITE / "assets" / "js" / "nav.js"
    nav = nav_path.read_text()
    block = "/* scenarios:begin */ " + json.dumps(nav_items, ensure_ascii=False) + " /* scenarios:end */"
    nav, count = re.subn(r"/\* scenarios:begin \*/.*?/\* scenarios:end \*/", lambda _: block, nav, flags=re.S)
    if count != 1:
        sys.exit("nav.js has no scenarios:begin/end block")
    nav_path.write_text(nav)
    # Scenario rows of the evidence inventory
    inventory_path = SITE / "EVIDENCE-INVENTORY.md"
    if inventory_path.exists():
        lines = ["| Scenario | Environment | Source evidence | Test date | Observed outcome | Status | Gaps |", "|---|---|---|---|---|---|---|"]
        for key, _ in GROUPS:
            for case, env in sorted(groups[key], key=lambda item: title_of(item[0])):
                seconds, down, up = traffic_of(case)
                numbers = (case.get("device") or {}).get("measured") or {}
                observed = (f"{seconds:.0f} s, down {megabytes(down)}, up {megabytes(up)}, errors: "
                            f"{'; '.join(numbers.get('errors') or []) or 'none'}" if seconds else
                            (case["result"].get("error") or "no traffic measured").splitlines()[-1][:120])
                lines.append(f"| [{title_of(case)}](waterwall/scenarios/{case['id']}.html) (`{case['id']}`) | {env['inventory_environment'].replace('{head}', env['head'])} | "
                             f"`evidence/{env['evidence_file']}`, case `{case['id']}` | {env['date'] or '—'} | "
                             f"{observed.replace('|', '/')} | {LABELS[status_of(case)]} | {env['inventory_gaps']} |")
        text, count = re.subn(r"<!-- scenarios:begin -->.*?<!-- scenarios:end -->",
                              lambda _: "<!-- scenarios:begin -->\n" + "\n".join(lines) + "\n<!-- scenarios:end -->",
                              inventory_path.read_text(), flags=re.S)
        if count == 1:
            inventory_path.write_text(text)
    print(f"rendered {sum(len(v) for v in groups.values())} scenario pages")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    x = sub.add_parser("extract")
    x.add_argument("--work", required=True)
    x.add_argument("--provenance", required=True)
    x.add_argument("--selection")
    x.add_argument("--kind", default="matrix", choices=["matrix", "lifecycle", "production", "download"])
    x.add_argument("--id-suffix", default="", help="added to each case id, for a case that also ran in another mode")
    x.add_argument("--server-ip", required=True)
    x.add_argument("--client-ip", required=True)
    x.add_argument("--server-host", default="", help="the server's DNS name, replaced by <SERVER_HOST>")
    x.add_argument("--device-id", default="")
    x.add_argument("--secrets-file", help="file with one secret per line, replaced by <PASSWORD>")
    x.add_argument("--environment", help='JSON such as {"profile": "device-matrix"}')
    x.add_argument("--output", required=True)
    r = sub.add_parser("render")
    r.add_argument("--evidence", nargs="+", required=True)
    r.add_argument("--environment", required=True, help="JSON file with the shared text for each test profile")
    r.add_argument("--intro", help="HTML for the top of the overview page")
    args = parser.parse_args()
    extract(args) if args.command == "extract" else render(args)


if __name__ == "__main__":
    main()
