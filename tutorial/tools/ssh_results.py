#!/usr/bin/env python3
"""Turns the SSH VPN test runs of both phones into ssh/results.html (after sslvpn_results.py).

  extract  reads the iPhone runner's and the Android runners' results.json files with the case list and writes one
           sanitized evidence file; a later file's run of a case replaces an earlier one
  render   writes ssh/results.html from an evidence file
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from softether_results import e, lifecycle_words  # noqa: E402
from sslvpn_results import cell  # noqa: E402
from sstp_results import Sanitizer, merged  # noqa: E402
from waterwall_scenarios import LOCAL_PATH, PUBLIC_IPV4  # noqa: E402

SITE = Path(__file__).resolve().parent.parent
GROUPS = [
    ("Transfers and UDP", lambda i: re.match(r"ssh-(pass|many|udp)", i)),
    ("Logins", lambda i: re.match(r"ssh-(wrong|special|password|kbd|no-forwarding)", i)),
    ("Host Key", lambda i: i.startswith("ssh-hostkey")),
    ("Server and Port", lambda i: re.match(r"ssh-(port|host-)", i)),
    ("Server settings", lambda i: i.startswith("ssh-server")),
    ("Log levels", lambda i: i.startswith("ssh-log")),
    ("Sleep, lost connections, network switch and Retry Times", lambda i: "-life-" in i or i.startswith("ssh-retry")),
    ("The server as the guide sets it up", lambda i: i.startswith("ssh-guide")),
]
TRAFFIC = {"download": "download", "upload": "upload", "full-duplex": "download and upload at once", "none": "connect only"}
KEYS = {"ssh-hostkey-ed25519": "the fingerprint of the server's ED25519 key",
        "ssh-hostkey-ecdsa-not-shown": "the fingerprint of the server's ECDSA key",
        "ssh-hostkey-rsa-not-shown": "the fingerprint of the server's RSA key",
        "ssh-hostkey-wrong": "a fingerprint of no key of the server",
        "ssh-hostkey-keygen-line": "the whole line ssh-keygen -lf prints for the server's ED25519 key",
        "ssh-server-hostkey-ed25519": "the fingerprint of the server's ED25519 key",
        "ssh-server-hostkey-ecdsa": "the fingerprint of the server's ECDSA key",
        "ssh-server-hostkey-rsa": "the fingerprint of the server's RSA key",
        "ssh-guide-udp-download": "the fingerprint of the server's ED25519 key"}
PORTS = {"": "Port empty", "2222": "Port 2222 (the server's second SSH port)", "2223": "Port 2223 (nothing listens on it)",
         "2224": "Port 2224 (a service that does not speak SSH answers it)"}
NOTES = {
    "ssh-special-password": "a user whose password has spaces, punctuation and letters outside ASCII",
    "ssh-guide-udp-download": "the user, sshd file and UDP relay that OpenSSH server sets up",
    "ssh-wrong-user": "a user the server does not have",
    "ssh-no-forwarding": "a user the server does not let forward TCP (AllowTcpForwarding no)",
    "ssh-password-login-off": "server: PasswordAuthentication no for the user",
    "ssh-kbd-interactive-only": "server: PasswordAuthentication no and KbdInteractiveAuthentication yes for the user",
    "ssh-udp-relay-stopped": "server: the UDP relay stopped", "ssh-udp-off-relay-stopped": "server: the UDP relay stopped",
    "ssh-port-no-answer": "server: every new connection to port 2222 dropped",
    "ssh-server-hardened": "server: KexAlgorithms curve25519-sha256 only, Ciphers chacha20-poly1305 and aes256-gcm, "
                           "MACs hmac-sha2 ETM only",
    "ssh-server-aes-gcm": "server: Ciphers aes256-gcm and aes128-gcm only",
    "ssh-server-aes-ctr": "server: Ciphers aes256-ctr and aes128-ctr only",
    "ssh-server-chacha": "server: Ciphers chacha20-poly1305 only",
    "ssh-server-hostkey-ed25519": "server: HostKeyAlgorithms ssh-ed25519",
    "ssh-server-hostkey-ecdsa": "server: HostKeyAlgorithms ecdsa-sha2-nistp256",
    "ssh-server-hostkey-rsa": "server: HostKeyAlgorithms rsa-sha2-512,rsa-sha2-256",
    "ssh-server-banner": "server: Banner /etc/issue.net",
    "ssh-server-keepalive-idle": "server: ClientAliveInterval 5, ClientAliveCountMax 2",
    "ssh-retry-before-connect": "server: port 2222 refuses connections",
    "ssh-life-server-ends-reconnect": "the server ends the session", "ssh-life-server-ends-no-reconnect": "the server ends the session",
    "ssh-life-reset-reconnect": "the server resets the TCP connection", "ssh-life-reset-no-reconnect": "the server resets the TCP connection",
    "ssh-life-retry-exhausted": "the server ends the session and refuses new connections",
    "ssh-life-outage-reconnect": "the server ends the session and refuses new connections for 8 s",
    "ssh-life-silent-drop-reconnect": "server: every packet of the session dropped, no reset, until the app tries a new connection",
}
LOGINS = {"password": "the server logged a password login", "keyboard-interactive/pam": "the server logged a keyboard-interactive login"}
LOG_WORDS = {"SSH connecting to": "the connect line", "[ssh] SSH: server host key ED25519 SHA256:": "the server's host key",
             "[ssh] SSH: logged in as": "the login line", "SSH: session established": "the session line",
             "[ssh] SSH: stats up=": "the transfer counters", "[ssh] SSH: flow fd ": "a line for each connection",
             "[ssh] SSH: engine starting": "the packet engine's start line",
             "] [D] ": "the packet engine's own lines",
             "SSH: closing with reason: Authentication failed": "the reason the app closed the connection",
             "<runner-redacted-secret>": "the password"}
# the Android lifecycle tool names its cases android-life-*; they stand beside the iPhone's ssh-life-* rows
LIFE = {"ssh-life-sleep-modes": ["android-life-sleep-stay", "android-life-sleep-pause", "android-life-sleep-off-reconnects",
                                 "android-life-sleep-off-ends"],
        "ssh-life-server-ends-reconnect": ["android-life-peer-drop-reconnect"],
        "ssh-life-server-ends-no-reconnect": ["android-life-peer-drop-no-reconnect"],
        "ssh-life-reset-reconnect": ["android-life-reset-reconnect"],
        "ssh-life-reset-no-reconnect": ["android-life-reset-no-reconnect"],
        "ssh-life-path-switch": ["android-life-wifi-switch"],
        "ssh-life-retry-exhausted": ["android-life-retry-exhausted"],
        "ssh-life-outage-reconnect": ["android-life-outage-reconnect"],
        "ssh-life-silent-drop-reconnect": ["android-life-silent-drop-reconnect"]}


def settings_of(case):
    """What the case sets, in the profile editor's words."""
    profile, cid = case["profile"], case["id"]
    items = []
    server = profile.get("server", "")
    if server.startswith("no-such-host"):
        items.append("Server is a name that does not exist")
    elif not server.replace(".", "").isdigit():
        items.append("Server is a DNS name of the server")
    if profile.get("port", "22") != "22":
        items.append(PORTS[profile["port"]])
    if cid in KEYS:
        items.append("Host Key: " + KEYS[cid])
    if profile.get("sshUdpRelay"):
        items.append("UDP Relay on")
    if case.get("password_suffix"):
        items.append("wrong password")
    if cid in NOTES:
        items.append(NOTES[cid])
    if "logLevel" in profile:
        items.append("Log Level " + ["Normal", "Expert", "Debug"][profile["logLevel"]])
    if "-life-" in cid:
        if "sleep-modes" in cid:
            items.append("On Sleep Stay, Pause and Off, and Off with Auto Reconnect off")
        else:
            items.append("Auto Reconnect " + ("on" if profile.get("autoReconnect") else "off"))
    if profile.get("retryTimes"):
        items.append(f"Retry Times {profile['retryTimes']}")
    return items or ["defaults"]


def traffic_of(case):
    traffic = case.get("traffic", "download")
    if case["id"] == "ssh-server-keepalive-idle":
        return "connect, then 40 s without traffic"
    words = f"{case['connections']} downloads at once" if case.get("connections") else TRAFFIC[traffic]
    if traffic != "none" and case.get("expect") != "fail":
        words += f", {case.get('duration', 60)} s"
    if "udp_expect" in case:
        words += ", and a DNS query over UDP"
    return words


def log_facts(result):
    check = (result or {}).get("log_check") or {}
    if not check:
        return []
    def words(prefix, value):
        return list(dict.fromkeys(LOG_WORDS[key[len(prefix):]] for key, ok in check.items() if key.startswith(prefix) and ok == value))
    facts = [] if check.get("log fetched", True) else ["no log came back"]
    for label, prefix, value in (("in the log", "has ", True), ("not in the log", "lacks ", True),
                                 ("missing from the log", "has ", False), ("also in the log", "lacks ", False)):
        if words(prefix, value):
            facts.append(f"{label}: " + ", ".join(words(prefix, value)))
    return facts


def facts_of(result, egress, clean):
    facts = ["Release build"] if result.get("configuration") == "Release" else []
    server_log = "\n".join(result.get("server_log") or [])
    login = re.search(r"Accepted (\S+) for", server_log)
    if login:
        facts.append(LOGINS.get(login[1], f"the server logged: Accepted {login[1]}"))
    elif "Failed password for invalid user" in server_log:
        facts.append("the server logged an unknown user")
    elif "Failed password for" in server_log:
        facts.append("the server logged a wrong password")
    for answer in result.get("udp_dns") or []:
        if answer.startswith(egress + " "):
            facts.append("the UDP DNS query was answered, and saw the server's address")
        elif answer.startswith("no answer"):
            facts.append("the UDP DNS query got no answer")
        else:
            facts.append("the UDP DNS query saw " + clean.text(answer))
    attempt = re.search(r"new connection attempt (\d+) s after the drop", "\n".join(result.get("marker_outputs") or []))
    if attempt:
        facts.append(f"the server saw the app's new connection attempt {attempt[1]} s after the path went dead")
    for line in result.get("idle") or []:
        # the iPhone: "40 seconds, HTTPS before=1 after=1, VPN status 2"; Android: "40 seconds, transfer before=1 after=1, VPN connected"
        idle = re.match(r"(\d+) seconds, (?:HTTPS|transfer) before=1 after=1, VPN (?:status 2|connected)$", line)
        facts.append(f"idle for {idle[1]} s: traffic worked before and after, and the VPN stayed connected" if idle
                     else "idle: " + clean.text(line))
    return facts + log_facts(result)


def ios_result(case, result, clean, egress):
    if result is None:
        return None
    entry = {"status": result.get("status"), "facts": facts_of(result, egress, clean)}
    if result.get("download"):
        entry["download_mbps"] = result["download"]["mbps"]
    both = result.get("full_duplex")
    if both and case.get("traffic") == "upload":
        entry["facts"].insert(0, f"up {both['upload_mbps']} Mbit/s")
    elif both:
        entry["download_mbps"], entry["upload_mbps"] = both["download_mbps"], both["upload_mbps"]
    if result.get("expected_failure"):
        entry["message"] = clean.text(result["expected_failure"]["message"])
    if result.get("lifecycle"):
        # lifecycle_words names SoftEther's server stop; here the port refuses connections, as the row says
        entry["lifecycle"] = [clean.text(lifecycle_words(": ".join(item))).replace("the server was stopped: ", "").replace("path-switch: ", "")
                              for item in result["lifecycle"]]
    moves = case.get("traffic", "download") != "none" and case.get("expect") != "fail"
    entry["through_server"] = egress in (result.get("stress_sources") or {}) if moves else None
    return entry


def android_result(result, clean, egress):
    if result is None:
        return None
    entry = {"status": "passed" if result.get("passed") else "failed", "transfer_s": result.get("transfer_s"),
             "facts": facts_of(result, egress, clean)}
    if result.get("message"):
        entry["message"] = clean.text(result["message"])
    if result.get("error"):
        entry["error"] = clean.text(result["error"])
    if result.get("lifecycle"):
        entry["lifecycle"] = [clean.text(item) for item in result["lifecycle"]]
    return entry


def extract(args):
    clean = Sanitizer(dict(pair.split("=", 1) for pair in args.replace))
    cases = [case for path in args.cases for case in json.loads(Path(path).read_text())]
    ios, android = merged(args.ios), merged(args.android)
    out = []
    for case in cases:
        droid = android.get(case["id"])
        if case["id"] in LIFE:
            parts = [android[name] for name in LIFE[case["id"]] if name in android]
            droid = {"passed": all(part.get("passed") for part in parts),
                     "lifecycle": [note for part in parts for note in (part.get("lifecycle") or [part.get("error", "")])]} if parts else None
        if case["id"] not in ios and droid is None:
            continue
        out.append({"id": case["id"], "settings": settings_of(case), "traffic": traffic_of(case),
                    "expect": case.get("expect", "connect"), "iphone": ios_result(case, ios.get(case["id"]), clean, args.egress),
                    "android": android_result(droid, clean, args.egress)})
    evidence = {"run": {"date": args.date, "iphone": args.iphone, "android": args.android_device, "app": args.app, "server": args.server},
                "summary": {"cases": len(out),
                            "iphone_passed": sum(1 for case in out if case["iphone"] and case["iphone"]["status"] == "passed"),
                            "iphone_run": sum(1 for case in out if case["iphone"]),
                            "android_passed": sum(1 for case in out if case["android"] and case["android"]["status"] == "passed"),
                            "android_run": sum(1 for case in out if case["android"])},
                "cases": out}
    text = json.dumps(evidence, indent=1)
    leaks = sorted(set(PUBLIC_IPV4.findall(text)))
    if leaks:
        sys.exit(f"Public addresses left in the evidence: {leaks}")
    if LOCAL_PATH.search(text):
        sys.exit("A local path is left in the evidence")
    # a real host key fingerprint names the test server as surely as its address
    if re.search(r"SHA256:[A-Za-z0-9+/]{43}", text):
        sys.exit("A host key fingerprint is left in the evidence: replace it with --replace")
    Path(args.output).write_text(text + "\n")
    print(f"{len(out)} cases; iPhone {evidence['summary']['iphone_passed']}/{evidence['summary']['iphone_run']}, "
          f"Android {evidence['summary']['android_passed']}/{evidence['summary']['android_run']}")


def render(args):
    evidence = json.loads(Path(args.evidence).read_text())
    run, summary = evidence["run"], evidence["summary"]
    sections = []
    for title, matches in GROUPS:
        rows = [case for case in evidence["cases"] if matches(case["id"])]
        if not rows:
            continue
        body = [f"<tr><td><code>{e(case['id'])}</code></td><td>{e('; '.join(case['settings']))}</td><td>{e(case['traffic'])}</td>"
                f"<td>{'connect' if case['expect'] == 'connect' else 'refused'}</td><td>{cell(case['iphone'], 'iphone')}</td>"
                f"<td>{cell(case['android'], 'android')}</td></tr>" for case in rows]
        anchor = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
        sections.append(f'<h2 id="{anchor}">{e(title)}</h2>\n<div class="table-scroll"><table>\n'
                        '<thead><tr><th>Case</th><th>Settings</th><th>Traffic</th><th>Expected</th><th>iPhone</th><th>Android</th></tr></thead>\n'
                        "<tbody>\n" + "\n".join(body) + "\n</tbody></table></div>")
    page = (SITE / "tools" / "ssh-results-intro.html").read_text()
    for key, value in run.items():
        page = page.replace("{" + key + "}", e(value))
    for key in ("iphone_passed", "iphone_run", "android_passed", "android_run"):
        page = page.replace("{" + key + "}", str(summary[key]))
    page = page.replace("{sections}", "\n\n".join(sections))
    (SITE / "ssh" / "results.html").write_text(page)
    print("wrote ssh/results.html")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("extract")
    one.add_argument("--cases", nargs="+", required=True)
    one.add_argument("--ios", nargs="*", default=[])
    one.add_argument("--android", nargs="*", default=[])
    one.add_argument("--replace", nargs="*", default=[], help="real=placeholder pairs")
    one.add_argument("--egress", required=True, help="the address the clients' traffic leaves the VPN server from")
    one.add_argument("--date", required=True)
    one.add_argument("--iphone", required=True)
    one.add_argument("--android-device", required=True)
    one.add_argument("--app", required=True)
    one.add_argument("--server", required=True)
    one.add_argument("--output", required=True)
    two = sub.add_parser("render")
    two.add_argument("--evidence", required=True)
    args = parser.parse_args()
    extract(args) if args.command == "extract" else render(args)


if __name__ == "__main__":
    main()
