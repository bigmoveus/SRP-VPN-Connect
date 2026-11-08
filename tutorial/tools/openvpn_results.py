#!/usr/bin/env python3
"""Turns the OpenVPN test runs of both phones into openvpn/results.html (after ssh_results.py).

  extract  reads the iPhone runner's and the Android runners' results.json files with the case list and writes one
           sanitized evidence file; a later file's run of a case replaces an earlier one
  render   writes openvpn/results.html from an evidence file
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
    ("Transfers and UDP", lambda i: re.match(r"ovpn-(udp|tcp|stunnel)-(download|full-duplex|upload|many-connections|probe)$", i)),
    ("Username and password", lambda i: i.startswith("ovpn-pass")),
    ("Server and Port", lambda i: re.match(r"ovpn-(port|server|two)-", i)),
    ("stunnel", lambda i: i.startswith("ovpn-stunnel") and not re.search(r"-(download|full-duplex|upload)$", i)),
    ("TLS Fragmentation", lambda i: i.startswith("ovpn-frag")),
    ("Refusals and damaged profiles", lambda i: re.match(r"ovpn-(revoked|rogue|wrong|udp-closed|tcp-refused|unknown|garbage|encrypted|static)", i)),
    ("Older servers", lambda i: re.match(r"ovpn-(net30|cbc|pushed)", i)),
    ("Log levels", lambda i: i.startswith("ovpn-log") or i.startswith("ovpn-release")),
    ("Sleep, lost connections, network switch and Retry Times", lambda i: "-life-" in i),
    ("The server as the guide sets it up", lambda i: i.startswith("ovpn-guide")),
]
TRAFFIC = {"download": "download", "upload": "upload", "full-duplex": "download and upload at once", "none": "connect only"}
PROFILES = {
    "pki/ovpn-cert1-udp.ovpn": "UDP profile, certificate login", "pki/ovpn-cert1-tcp.ovpn": "TCP profile, certificate login",
    "pki/ovpn-cert1-stunnel.ovpn": "stunnel profile (TCP to port 443), certificate login",
    "pki/ovpnuser-udp-pass.ovpn": "UDP profile, password login", "pki/ovpnuser-tcp-pass.ovpn": "TCP profile, password login",
    "pki/ovpnuser-stunnel-pass.ovpn": "stunnel profile (TCP to port 8443), password login",
    "pki/ovpn-revoked-udp.ovpn": "UDP profile with a revoked certificate",
    "pki/derived-rogue-client.ovpn": "UDP profile with a client certificate of another CA",
    "pki/derived-wrong-ca.ovpn": "UDP profile whose CA did not sign the server's certificate",
    "pki/derived-bad-tls-crypt.ovpn": "UDP profile with another tls-crypt key",
    "pki/derived-wrong-port.ovpn": "UDP profile whose remote line names port 1199 (nothing listens)",
    "pki/derived-tcp-refused.ovpn": "TCP profile whose remote line names port 1199 (nothing listens)",
    "pki/derived-bad-host.ovpn": "UDP profile whose remote line names a host that does not exist",
    "pki/derived-two-remotes.ovpn": "UDP profile with two remote lines: port 1199 (nothing listens), then port 1194",
    "pki/derived-garbage.ovpn": "a file with remote and dev lines but no profile",
    "pki/derived-encrypted-key.ovpn": "UDP profile whose private key has a passphrase",
    "pki/derived-static-key.ovpn": "a static-key (secret) profile",
    "pki/ovpn-cert1-net30.ovpn": "UDP profile, certificate login", "pki/ovpn-cert1-cbc.ovpn": "UDP profile with tls-auth, auth SHA256, cipher AES-256-CBC",
    "pki/ovpn-cert1-comp.ovpn": "UDP profile, certificate login",
    "pki/guide-phone1-udp.ovpn": "the guide's phone1-udp.ovpn", "pki/guide-phone1-stunnel.ovpn": "the guide's phone1-stunnel.ovpn",
    "pki/guide-vpnuser-udp-pass.ovpn": "the guide's vpnuser-udp-pass.ovpn", "pki/guide-vpnuser-tcp-pass.ovpn": "the guide's vpnuser-tcp-pass.ovpn",
    "pki/guide-vpnuser-stunnel-pass.ovpn": "the guide's vpnuser-stunnel-pass.ovpn",
    "pki/guide-phone2-udp.ovpn": "the guide's phone2-udp.ovpn, phone2 revoked as part 9 says",
}
NOTES = {
    "ovpn-pass-special-characters": "a user whose password has spaces, punctuation and letters outside ASCII",
    "ovpn-net30-topology": "server: no topology line (net30)",
    "ovpn-cbc-tls-auth": "server: data-ciphers AES-256-CBC, auth SHA256, tls-auth instead of tls-crypt",
    "ovpn-pushed-compression": "server: allow-compression yes, compress lz4-v2 pushed",
    "ovpn-stunnel-private-ca": "stunnel on port 9443 with a certificate of its own CA",
    "ovpn-stunnel-private-no-ca": "stunnel on port 9443 with a certificate of its own CA",
    "ovpn-stunnel-private-wrong-ca": "stunnel on port 9443 with a certificate of its own CA",
    "ovpn-stunnel-custom-sni": "stunnel on port 9443 whose certificate has a second name",
    "ovpn-frag-auto-private-ca-sni": "stunnel on port 9443 whose certificate has a second name",
    "ovpn-stunnel-tls12-only": "server: stunnel on port 9444 with sslVersionMax = TLSv1.2",
    "ovpn-stunnel-closed-port": "nothing listens on stunnel port 4443",
    "ovpn-life-kick-udp": "the server restarts the session (client-kill)", "ovpn-life-kick-udp-no-reconnect": "the server restarts the session (client-kill)",
    "ovpn-life-kick-tcp": "the server restarts the session (client-kill)",
    "ovpn-life-halt": "the server halts the session (client-kill HALT)",
    "ovpn-life-stunnel-restart": "stunnel restarts", "ovpn-life-stunnel-restart-no-reconnect": "stunnel restarts",
    "ovpn-life-retry-exhausted-udp": "the server stops for 120 s", "ovpn-life-retry-exhausted-stunnel": "the TCP server behind stunnel stops for 120 s",
    "ovpn-life-outage-reconnect": "the server stops for 8 s",
    "ovpn-life-dead-path-reconnects": "every packet of the session dropped for 45 s",
    "ovpn-life-dead-path-no-reconnect": "every packet of the session dropped for 150 s",
}
CA = {"pki/stunnel-ca.crt": "CA Certificate: the stunnel server's own CA", "pki/rogue-ca.crt": "CA Certificate: a CA that signed nothing on the server"}
LOG_WORDS = {"OpenVPN: session established": "the session line", "OpenVPN core:": "OpenVPN's own lines",
             "ovpn-to-phone": "packet lines (Debug build)", "OpenVPN: ": "the app's OpenVPN lines",
             "<runner-redacted-secret>": "the password", "BEGIN PRIVATE KEY": "the private key",
             "OpenVPN Static key": "the tls-crypt key", "ovpn-key-pass": "a key passphrase"}
# the Android lifecycle tool names its cases android-life-*; they stand beside the iPhone's ovpn-life-* rows
LIFE = {"ovpn-life-sleep-modes-udp": ["android-life-sleep-stay", "android-life-sleep-pause", "android-life-sleep-off-reconnects",
                                      "android-life-sleep-off-ends"],
        "ovpn-life-kick-udp": ["android-life-kick-reconnect"],
        "ovpn-life-kick-udp-no-reconnect": ["android-life-kick-no-reconnect"],
        "ovpn-life-halt": ["android-life-halt"],
        "ovpn-life-stunnel-restart": ["android-life-stunnel-restart-reconnect"],
        "ovpn-life-stunnel-restart-no-reconnect": ["android-life-stunnel-restart-no-reconnect"],
        "ovpn-life-path-switch-udp": ["android-life-wifi-switch"],
        "ovpn-life-retry-exhausted-udp": ["android-life-retry-exhausted"],
        "ovpn-life-outage-reconnect": ["android-life-outage-reconnect"],
        "ovpn-life-dead-path-reconnects": ["android-life-silent-drop-reconnect"]}


def settings_of(case):
    """What the case sets, in the profile editor's words."""
    profile, cid = case["profile"], case["id"]
    items = [PROFILES.get(case.get("profile_file", ""), "a profile of the server")]
    server = profile.get("server", "")
    if server.startswith("no-such-host"):
        items.append("Server is a name that does not exist")
    elif server.replace(".", "").isdigit():
        items.append("Server is the server's address")
    if cid in ("ovpn-port-field-overrides-profile", "ovpn-two-remotes-failover", "ovpn-udp-closed-port", "ovpn-tcp-refused"):
        items.append(f"Port {profile.get('port')}")
    if profile.get("ovpnStunnelEnabled"):
        stunnel = ["stunnel on"]
        if profile.get("ovpnStunnelHost"):
            stunnel.append("stunnel Host: the server's name (Server: its address)")
        if profile.get("ovpnStunnelPort"):
            stunnel.append(f"stunnel Port {profile['ovpnStunnelPort']}")
        if profile.get("ovpnStunnelSNI"):
            stunnel.append(f"stunnel SNI {profile['ovpnStunnelSNI']}")
        items.extend(stunnel)
    if case.get("stunnel_ca_file"):
        items.append(CA[case["stunnel_ca_file"]])
    mode = profile.get("tlsFragMode")
    if mode is not None and profile.get("ovpnStunnelEnabled"):
        items.append("TLS Fragmentation " + ["Off", "Auto", "Manual"][mode] +
                     (f" {profile.get('tlsFragFirst') or 32}/{profile.get('tlsFragFollowing') or 256}" if mode == 2 else ""))
    if case.get("password_suffix"):
        items.append("wrong password")
    if cid in NOTES:
        items.append(NOTES[cid])
    if "logLevel" in profile and (cid.startswith("ovpn-log") or cid.startswith("ovpn-release")):
        items.append("Log Level " + ["Normal", "Expert", "Debug"][profile["logLevel"]])
    if "-life-" in cid:
        if "sleep-modes" in cid:
            items.append("On Sleep Stay, Pause and Off, and Off with Auto Reconnect off")
        elif "path-switch" in cid:
            items.append("Auto Reconnect " + ("on" if profile.get("autoReconnect") else "off") + "; the connection moved to a new network path")
        else:
            items.append("Auto Reconnect " + ("on" if profile.get("autoReconnect") else "off"))
    if profile.get("retryTimes"):
        items.append(f"Retry Times {profile['retryTimes']}")
    return items


def traffic_of(case):
    traffic = case.get("traffic", "download")
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


def facts_of(case, result, egress, clean):
    facts = ["Release build"] if result.get("configuration") == "Release" else []
    outputs = "\n".join((result.get("marker_outputs") or []) + (result.get("after_outputs") or []))
    client = re.search(r"client (\S+) real=(\S+?):\d+ vpn=(\S+) .*cipher=(\S+)", outputs)
    if client:
        through = "through stunnel (127.0.0.1)" if client[2] == "127.0.0.1" else "directly"
        facts.append(f"the server listed the client {client[1]} {through}, tunnel address {client[3]}, cipher {client[4]}")
    # the guide's server has no management interface: its log names the client, its address and cipher
    initiated = re.search(r"\[(\S+)\] Peer Connection Initiated with \[AF_INET\](\S+?):\d+", outputs)
    if initiated:
        address = re.search(r"MULTI: primary virtual IP for \S+ (\S+)$", outputs, re.M)
        cipher = re.search(r"Data Channel: cipher '([^']+)'", outputs)
        through = "through stunnel (127.0.0.1)" if initiated[2] == "127.0.0.1" else "directly"
        facts.append(f"the server's log: {initiated[1]} connected {through}" + (f", tunnel address {address[1]}" if address else "") +
                     (f", cipher {cipher[1]}" if cipher else ""))
    listed = re.search(r"^CLIENT_LIST,([^,]+),", outputs, re.M)
    if listed:
        facts.append(f"70 s after connecting, the status file listed {listed[1]}")
    pieces = re.search(r"^((?:\d+ )+)", "\n".join(result.get("after_outputs") or []), re.M) if case["id"].startswith("ovpn-frag") else None
    if pieces:
        sizes = pieces[1].split()
        facts.append("the server received the ClientHello as TCP segments of " + ", ".join(sizes[:6]) + (" … bytes" if len(sizes) > 6 else " bytes"))
    server_log = "\n".join(result.get("server_log") or [])
    verify = re.search(r"VERIFY ERROR: depth=\d+, error=([^:]+)", server_log)
    if verify:
        facts.append(f"the server's log: VERIFY ERROR: {verify[1]}")
    if "Auth Username/Password verification failed" in server_log or "AUTH_FAILED" in server_log and case.get("password_suffix"):
        facts.append("the server's log: the username/password check failed")
    if "HMAC" in server_log and "wrong-tls-crypt" in case["id"]:
        facts.append("the server dropped the packets (its log: TLS Error: tls-crypt unwrapping failed)")
    cipher = re.search(r"Data Channel: cipher '([^']+)'(?:, auth '([^']+)')?", server_log)
    if cipher and not client and not initiated:
        facts.append(f"the server's log: data channel {cipher[1]}" + (f" with {cipher[2]}" if cipher[2] else ""))
    for answer in result.get("udp_dns") or []:
        if answer.startswith(egress + " "):
            facts.append("the UDP DNS query was answered, and saw the server's address")
        elif answer.startswith("no answer"):
            facts.append("the UDP DNS query got no answer")
        else:
            facts.append("the UDP DNS query saw " + clean.text(answer))
    for line in result.get("idle") or []:
        idle = re.match(r"(\d+) seconds, (?:HTTPS|transfer) before=1 after=1, VPN (?:status 2|connected)$", line)
        facts.append(f"held for {idle[1]} s while the server listed the client" if idle else "idle: " + clean.text(line))
    return facts + log_facts(result)


def ios_result(case, result, clean, egress):
    if result is None:
        return None
    entry = {"status": result.get("status"), "facts": facts_of(case, result, egress, clean)}
    if result.get("download"):
        entry["download_mbps"] = result["download"]["mbps"]
    both = result.get("full_duplex")
    if both and case.get("traffic") == "upload":
        entry["facts"].insert(0, f"up {both['upload_mbps']} Mbit/s")
    elif both:
        entry["download_mbps"], entry["upload_mbps"] = both["download_mbps"], both["upload_mbps"]
    if result.get("expected_failure"):
        entry["message"] = clean.text(result["expected_failure"]["message"])
        entry["facts"].append(f"ended after {result['expected_failure']['seconds']} s")
    if result.get("lifecycle"):
        entry["lifecycle"] = [clean.text(lifecycle_words(": ".join(item))).replace("the server was stopped: ", "").replace("path-switch: ", "")
                              for item in result["lifecycle"]]
    moves = case.get("traffic", "download") != "none" and case.get("expect") != "fail"
    entry["through_server"] = egress in (result.get("stress_sources") or {}) if moves else None
    return entry


def android_result(case, result, clean, egress):
    if result is None:
        return None
    entry = {"status": "passed" if result.get("passed") else "failed", "transfer_s": result.get("transfer_s"),
             "facts": facts_of(case, result, egress, clean) if "id" in case else []}
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
                    "android": android_result(case, droid, clean, args.egress)})
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
    page = (SITE / "tools" / "openvpn-results-intro.html").read_text()
    for key, value in run.items():
        page = page.replace("{" + key + "}", e(value))
    for key in ("iphone_passed", "iphone_run", "android_passed", "android_run"):
        page = page.replace("{" + key + "}", str(summary[key]))
    page = page.replace("{sections}", "\n\n".join(sections))
    (SITE / "openvpn" / "results.html").write_text(page)
    print("wrote openvpn/results.html")


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
