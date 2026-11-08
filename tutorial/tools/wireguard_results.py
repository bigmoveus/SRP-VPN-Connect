#!/usr/bin/env python3
"""Turns the WireGuard test runs of both phones into wireguard/results.html (after openvpn_results.py).

  extract  reads the iPhone runner's and the Android runners' results.json files with the case list and writes one
           sanitized evidence file; a later file's run of a case replaces an earlier one
  render   writes wireguard/results.html from an evidence file
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
    ("Transfers and UDP", lambda i: re.match(r"wg-(download|upload|full-duplex|many-connections|udp-probe)$", i)),
    ("The configuration", lambda i: re.match(r"wg-(no-psk|no-keepalive|mtu-1280|endpoint-ip|split-tunnel|manual-configuration)$", i)),
    ("Server and Port", lambda i: re.match(r"wg-(port|server)-field", i)),
    ("Refusals and damaged files", lambda i: re.match(r"wg-(wrong|unknown|closed|bad|no-address|garbage|retry-before)", i)),
    ("Log levels", lambda i: i.startswith("wg-log") or i.startswith("wg-release")),
    ("Sleep, a server that goes away, network changes and Retry Times", lambda i: "-life-" in i),
    ("The server as the guide sets it up", lambda i: i.startswith("wg-guide")),
]
TRAFFIC = {"download": "download", "upload": "upload", "full-duplex": "download and upload at once", "none": "connect only"}
# The iPhone's files (keys/ios1.conf and what make_wg_cases.py derives from it); Android's are the same made from its own peer
PROFILES = {
    "keys/ios1.conf": "the phone's file: all IPv4 traffic, preshared key, keepalive 25 s",
    "keys/nopsk.conf": "a file and peer without a preshared key",
    "keys/wrongpsk.conf": "a file whose preshared key is not the server's for its peer",
    "keys/derived-no-keepalive.conf": "the phone's file without PersistentKeepalive",
    "keys/derived-mtu-1280.conf": "the phone's file with MTU = 1280",
    "keys/derived-endpoint-ip.conf": "the phone's file with the server's address as Endpoint",
    "keys/derived-split.conf": "the phone's file with AllowedIPs = 10.66.66.0/24",
    "keys/derived-closed-port.conf": "the phone's file with Endpoint port 51829 (nothing listens)",
    "keys/derived-unknown-host.conf": "the phone's file with an Endpoint name that does not exist",
    "keys/derived-wrong-server-key.conf": "the phone's file with a server public key of nobody",
    "keys/derived-unknown-client.conf": "the phone's file with a private key the server does not have",
    "keys/derived-bad-key.conf": "the phone's file with a damaged private key",
    "keys/derived-bad-psk.conf": "the phone's file with a damaged preshared key",
    "keys/derived-no-address.conf": "the phone's file without Address",
    "keys/derived-garbage.conf": "a file with [Interface] and [Peer] but no values",
    "keys/guide-phone1.conf": "the guide's phone1.conf",
    "keys/guide-phone2.conf": "the guide's phone2.conf, phone2 removed as part 5 says",
}
NOTES = {
    "wg-manual-configuration": "the same values entered under Manual Configuration instead of a file",
    "wg-life-server-restart": "the server's WireGuard restarts (wg-quick)",
    "wg-life-outage-reconnect": "the server's WireGuard stops for 8 s",
    "wg-life-server-down-no-reconnect": "the server's WireGuard stops for 150 s",
    "wg-life-retry-exhausted": "the server's WireGuard stops for 120 s",
    "wg-life-dead-path-reconnects": "every packet of the session dropped for 45 s",
}
LOG_WORDS = {"WireGuard: session established": "the session line", "WireGuard: last handshake": "the 30-second handshake and byte line",
             "[wg] ": "WireGuard's own lines", "PrivateKey": "a private key line", "PresharedKey": "a preshared key line",
             "private_key=": "the engine's private key", "preshared_key=": "the engine's preshared key"}
# the Android lifecycle tool names its cases android-life-*; they stand beside the iPhone's wg-life-* rows
LIFE = {"wg-life-sleep-modes": ["android-life-sleep-stay", "android-life-sleep-pause", "android-life-sleep-off-reconnects",
                                "android-life-sleep-off-ends"],
        "wg-life-server-restart": ["android-life-server-restart"],
        "wg-life-outage-reconnect": ["android-life-outage-reconnect"],
        "wg-life-server-down-no-reconnect": ["android-life-server-down-no-reconnect"],
        "wg-life-retry-exhausted": ["android-life-retry-exhausted"],
        "wg-life-dead-path-reconnects": ["android-life-silent-drop-reconnect"],
        "wg-life-path-switch": ["android-life-wifi-switch"]}


def settings_of(case):
    """What the case sets, in the profile editor's words."""
    profile, cid = case["profile"], case["id"]
    items = [PROFILES.get(case.get("profile_file", ""), "a file of the server")]
    if cid in ("wg-port-field-overrides-profile", "wg-retry-before-connect"):
        items.append(f"Port {profile.get('port')}")
    if cid == "wg-server-field-overrides-profile":
        items.append("Server: the server's name")
    if cid in NOTES:
        items.append(NOTES[cid])
    if "logLevel" in profile and cid.startswith(("wg-log", "wg-release")):
        items.append("Log Level " + ["Normal", "Expert", "Debug"][profile["logLevel"]])
    if "-life-" in cid:
        if "sleep-modes" in cid:
            items.append("On Sleep Stay, Pause and Off, and Off with Auto Reconnect off")
        elif "path-switch" in cid:
            items.append("the connection moved to the current network")
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
    if "udp_expect" in case or "udp_expect_not" in case:
        words += ", and a DNS query over UDP"
    return words


def log_facts(result):
    check = (result or {}).get("log_check") or {}
    if not check:
        return []
    def words(prefix, value):
        return list(dict.fromkeys(LOG_WORDS.get(key[len(prefix):], key[len(prefix):]) for key, ok in check.items() if key.startswith(prefix) and ok == value))
    facts = [] if check.get("log fetched", True) else ["no log came back"]
    for label, prefix, value in (("in the log", "has ", True), ("not in the log", "lacks ", True),
                                 ("missing from the log", "has ", False), ("also in the log", "lacks ", False)):
        if words(prefix, value):
            facts.append(f"{label}: " + ", ".join(words(prefix, value)))
    return facts


def facts_of(case, result, server_ip, clean):
    facts = ["Release build"] if result.get("configuration") == "Release" else []
    outputs = "\n".join((result.get("marker_outputs") or []) + (result.get("after_outputs") or []))
    peer = re.search(r"^(?:peer|phone) (\S+) endpoint=\S+ handshake_age=(\d+)", outputs, re.M)
    if peer:
        facts.append(f"the server had a handshake with the peer {peer[1]} {peer[2]} s before it was asked")
    listed = re.search(r"^phone (\S+) endpoint=\S+ handshake_age=never", outputs, re.M)
    if listed:
        facts.append(f"the server never had a handshake with {listed[1]}")
    for answer in result.get("udp_dns") or []:
        if answer.startswith(server_ip + " "):
            facts.append("the UDP DNS query was answered, and saw the server's address")
        elif answer.startswith("no answer"):
            facts.append("the UDP DNS query got no answer")
        else:
            facts.append("the UDP DNS query was answered, and saw the phone's own network")
    if result.get("tunnel_ping"):
        facts.append("the server's tunnel address answered a ping: " + clean.text(result["tunnel_ping"]))
    for line in result.get("idle") or []:
        idle = re.match(r"(\d+) seconds, (?:HTTPS|transfer) before=1 after=1, VPN (?:status 2|connected)$", line)
        facts.append(f"held for {idle[1]} s" if idle else "idle: " + clean.text(line))
    return facts + log_facts(result)


def ios_result(case, result, clean, server_ip):
    if result is None:
        return None
    entry = {"status": result.get("status"), "facts": facts_of(case, result, server_ip, clean)}
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
    if result.get("source_check") is not None:
        entry["facts"].insert(0, "the transfers came through the tunnel (the stress server saw only the phone's tunnel address)"
                              if result["source_check"] else "the stress server also saw other addresses")
    return entry


def android_result(case, result, clean, server_ip):
    if result is None:
        return None
    entry = {"status": "passed" if result.get("passed") else "failed", "transfer_s": result.get("transfer_s"),
             "facts": facts_of(case, result, server_ip, clean) if "id" in case else []}
    if result.get("sources"):
        entry["facts"].insert(0, "the transfers came through the tunnel (the stress server saw only the phone's tunnel address)"
                              if result["sources"] == [case.get("source_expect")] else "the stress server saw other addresses")
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
    android_cases = {case["id"]: case for path in args.android_cases for case in json.loads(Path(path).read_text())}
    ios, android = merged(args.ios), merged(args.android)
    out, seen = [], set()
    for case in cases:
        if case["id"] in seen:
            continue
        seen.add(case["id"])
        droid = android.get(case["id"])
        if case["id"] in LIFE:
            parts = [android[name] for name in LIFE[case["id"]] if name in android]
            droid = {"passed": all(part.get("passed") for part in parts),
                     "lifecycle": [note for part in parts for note in (part.get("lifecycle") or [part.get("error", "")])]} if parts else None
        if case["id"] not in ios and droid is None:
            continue
        out.append({"id": case["id"], "settings": settings_of(case), "traffic": traffic_of(case),
                    "expect": case.get("expect", "connect"), "iphone": ios_result(case, ios.get(case["id"]), clean, args.server_ip),
                    "android": android_result(android_cases.get(case["id"], case), droid, clean, args.server_ip)})
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
    page = (SITE / "tools" / "wireguard-results-intro.html").read_text()
    for key, value in run.items():
        page = page.replace("{" + key + "}", e(value))
    for key in ("iphone_passed", "iphone_run", "android_passed", "android_run"):
        page = page.replace("{" + key + "}", str(summary[key]))
    page = page.replace("{sections}", "\n\n".join(sections))
    (SITE / "wireguard" / "results.html").write_text(page)
    print("wrote wireguard/results.html")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("extract")
    one.add_argument("--cases", nargs="+", required=True, help="the iPhone's case lists (their rows and settings)")
    one.add_argument("--android-cases", nargs="*", default=[], help="Android's case lists (the tunnel address each case expects)")
    one.add_argument("--ios", nargs="*", default=[])
    one.add_argument("--android", nargs="*", default=[])
    one.add_argument("--replace", nargs="*", default=[], help="real=placeholder pairs")
    one.add_argument("--server-ip", required=True, help="the server's public address, compared with the UDP DNS answers (never written)")
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
