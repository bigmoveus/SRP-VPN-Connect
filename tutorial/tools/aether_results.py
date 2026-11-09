#!/usr/bin/env python3
"""Turns the Aether test runs of both phones into aether/results.html (after wireguard_results.py).

  extract  reads the iPhone runner's and the Android runners' results.json files with the case list and writes one
           sanitized evidence file; a later file's run of a case replaces an earlier one
  render   writes aether/results.html from an evidence file
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from softether_results import e, lifecycle_words  # noqa: E402
from sslvpn_results import cell  # noqa: E402
from sstp_results import Sanitizer, merged  # noqa: E402
from waterwall_scenarios import LOCAL_PATH, PUBLIC_IPV4  # noqa: E402

SITE = Path(__file__).resolve().parent.parent
GROUPS = [
    ("Public mode: transports and transfers", lambda i: re.match(r"ae-(h3|h2|both|wg)-(download|upload|full-duplex)$|ae-scan-|ae-h2-frag-", i)),
    ("WARP+ and Tor", lambda i: re.match(r"ae-(warp-plus|tor)-", i)),
    ("Private mode", lambda i: re.match(r"ae-private-(download|upload)$", i)),
    ("Refusals and damaged files", lambda i: re.match(r"ae-private-(wrong|closed|unknown|bad|no-address|container|retry)", i)),
    ("Log levels", lambda i: re.match(r"ae-(private-)?log-|ae-release-", i)),
    ("Sleep, a session that ends, network changes, a server that goes away and Retry Times", lambda i: "-life-" in i),
    ("The server as the guide sets it up", lambda i: i.startswith("ae-guide")),
]
TRAFFIC = {"download": "download", "upload": "upload", "full-duplex": "download and upload at once", "none": "connect only"}
TRANSPORTS = {"masque": "MASQUE (HTTP/3)", "masque-h2": "MASQUE (HTTP/2)", "masque-both": "Both (H3 → H2)", "wg": "WireGuard"}
PROFILES = {
    "keys/private-client1.conf": "the phone's file from our server (AllowedIPs 10.66.66.0/24, keepalive 25 s, no preshared key)",
    "keys/private-wrong-server-key.conf": "the phone's file with a server public key of nobody",
    "keys/private-bad-key.conf": "the phone's file with a damaged private key",
    "keys/private-no-address.conf": "the phone's file without Address",
    "keys/guide-iphone1.conf": "the guide's file for each phone (iphone1 on the iPhone, android1 on Android)",
    "keys/guide-phone2.conf": "the guide's phone2.conf, phone2 removed as part 7 says",
}
NOTES = {
    "ae-private-closed-port": "Port 51829 (nothing listens)",
    "ae-private-unknown-host": "Server: a name that does not exist",
    "ae-private-container-down": "the server's aether container stopped",
    "ae-private-retry-before-connect": "Port 51829 (nothing listens)",
    "ae-life-session-drop": "the engine's session ended on purpose",
    "ae-life-session-drop-no-reconnect": "the engine's session ended on purpose",
    "ae-life-private-session-drop": "the WireGuard relay ended on purpose",
    "ae-life-private-outage-reconnect": "the server's WireGuard port drops everything for 40 s",
    "ae-life-private-server-down-no-reconnect": "the server's WireGuard port drops everything for 70 s",
    "ae-life-private-retry-exhausted": "the server's WireGuard port drops everything for 160 s",
    "ae-life-private-container-stopped": "the server's aether container stopped for 110 s",
}
LOG_WORDS = {"Aether: session established": "the session line", "Aether: auto reconnect on": "the options line",
             "test connection passed": "the Expert line of each test connection",
             "Aether: test connection passed; session up": "the Expert line of each test connection",
             "[srp] client cmd": "the engine's line for each connection", "socks5 client tcp": "the packet bridge's line for each connection",
             "socks5 client": "the packet bridge's line for each connection", "WARP+ license": "the WARP+ license lines",
             "continuing with free WARP": "the line saying WARP refused the license", "00000000-00000000-00000000": "the license key",
             "the PrivateKey value": "the file's private key", "the PresharedKey value": "the file's preshared key"}
# the Android lifecycle tool names its cases android-life-*; they stand beside the iPhone's ae-life-* rows
LIFE = {"ae-life-sleep-modes": ["android-life-sleep-stay", "android-life-sleep-pause", "android-life-sleep-off-reconnects",
                                "android-life-sleep-off-ends"],
        "ae-life-session-drop": ["android-life-session-drop"],
        "ae-life-session-drop-no-reconnect": ["android-life-session-drop-no-reconnect"],
        "ae-life-path-switch": ["android-life-wifi-switch"],
        "ae-life-private-sleep-modes": ["android-life-private-sleep-pause", "android-life-private-sleep-off-ends"],
        "ae-life-private-session-drop": ["android-life-private-session-drop"],
        "ae-life-private-outage-reconnect": ["android-life-private-outage-reconnect"],
        "ae-life-private-server-down-no-reconnect": ["android-life-private-server-down-no-reconnect"],
        "ae-life-private-retry-exhausted": ["android-life-private-retry-exhausted"],
        "ae-life-private-container-stopped": ["android-life-private-container-stopped"]}
ASNS = {}


def asn_of(address):
    """The AS number that announces address (Team Cymru's whois): only the number is written, never the address."""
    if address not in ASNS:
        out = subprocess.run(["whois", "-h", "whois.cymru.com", f" -v {address}"], capture_output=True, text=True, timeout=30).stdout
        numbers = [line.split("|")[0].strip() for line in out.splitlines() if "|" in line and line.split("|")[0].strip().isdigit()]
        ASNS[address] = f"AS{numbers[0]}" if numbers else "an unknown network"
    return ASNS[address]


def settings_of(case):
    """What the case sets, in the profile editor's words."""
    profile, cid = case["profile"], case["id"]
    if profile.get("aetherMode") == "private":
        items = ["Private", PROFILES.get(case.get("profile_file", ""), "a file of the server")]
    else:
        items = ["Public"]
        if profile.get("aetherTor") == "only":
            items.append("Tor: Tor Only")
        else:
            items.append("Transport " + TRANSPORTS[profile.get("aetherTransport", "masque-both")])
            if profile.get("aetherScan") == "turbo":
                items.append("Endpoint Scan Turbo")
            if profile.get("aetherTor") == "reverse":
                items.append("Tor: WARP via Tor")
            if profile.get("aetherLicense"):
                items.append("WARP+ License: a key WARP does not know")
            if profile.get("tlsFragMode") == 1:
                items.append("TLS Fragmentation Auto")
            elif profile.get("tlsFragMode") == 2:
                items.append(f"TLS Fragmentation Manual, {profile.get('tlsFragFirst')} to {profile.get('tlsFragFollowing')} bytes")
    if cid in NOTES:
        items.append(NOTES[cid])
    if cid.startswith(("ae-log", "ae-private-log", "ae-release")):
        items.append("Log Level " + ["Normal", "Expert", "Debug"][profile.get("logLevel", 1)])
    if "-life-" in cid:
        if "sleep-modes" in cid:
            items.append("On Sleep Stay, Pause and Off, and Off with Auto Reconnect off")
        elif "path-switch" in cid:
            items.append("a change of network (iPhone: the app's network change; Android: Wi-Fi off and on again)")
        else:
            items.append("Auto Reconnect " + ("on" if profile.get("autoReconnect") else "off"))
    if profile.get("retryTimes"):
        items.append(f"Retry Times {profile['retryTimes']}")
    return items


def traffic_of(case):
    traffic = case.get("traffic", "download")
    words = TRAFFIC[traffic]
    if traffic != "none" and case.get("expect") != "fail":
        words += f", {case.get('duration', 30)} s"
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


def source_fact(asns):
    if not asns:
        return []
    if asns == ["AS13335"]:
        return ["the traffic left the internet at Cloudflare (AS13335), as the stress server saw it"]
    return [f"the stress server saw {', '.join(asns)}, not Cloudflare"]


def facts_of(result):
    facts = ["Release build"] if result.get("configuration") == "Release" else []
    if (result.get("server_check") or {}).get("Receiving handshake initiation from peer"):
        facts.append("the server's WireGuard received the phone's handshake")
    return facts + log_facts(result)


def ios_result(case, result, clean):
    if result is None:
        return None
    entry = {"status": result.get("status"), "facts": facts_of(result)}
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
        entry["lifecycle"] = [clean.text(lifecycle_words(": ".join(item))).replace("the server was stopped: ", "")
                              .replace("path-switch: ", "").replace("session-drop: ", "") for item in result["lifecycle"]]
    asns = result.get("source_asns")
    if asns is None and result.get("stress_sources") and case.get("expect") != "fail":
        asns = sorted({asn_of(address) for address in result["stress_sources"]})
    entry["facts"][:0] = source_fact(asns)
    return entry


def android_result(case, result, clean):
    if result is None:
        return None
    entry = {"status": "passed" if result.get("passed") else "failed", "transfer_s": result.get("transfer_s"),
             "facts": facts_of(result)}
    asns = result.get("source_asns")
    if asns is None and result.get("sources") and case.get("expect") != "fail":
        asns = sorted({asn_of(address) for address in result["sources"]})
    entry["facts"][:0] = source_fact(asns)
    if result.get("message"):
        entry["message"] = clean.text(result["message"])
    if result.get("error"):
        entry["error"] = clean.text(result["error"])
    if result.get("lifecycle"):
        entry["lifecycle"] = [clean.text(item) for item in result["lifecycle"]]
    return entry


def extract(args):
    pairs = dict(pair.split("=", 1) for pair in args.replace)
    if not all(pairs):
        sys.exit("An empty value to replace: every --replace pair needs its real value")
    clean = Sanitizer(pairs)
    cases = [case for path in args.cases for case in json.loads(Path(path).read_text())]
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
                    "expect": case.get("expect", "connect"), "iphone": ios_result(case, ios.get(case["id"]), clean),
                    "android": android_result(case, droid, clean)})
    evidence = {"run": {"date": args.date, "iphone": args.iphone, "android": args.android_device, "app": args.app, "server": args.server},
                "summary": {"cases": len(out),
                            "iphone_passed": sum(1 for case in out if case["iphone"] and case["iphone"]["status"] == "passed"),
                            "iphone_run": sum(1 for case in out if case["iphone"]),
                            "android_passed": sum(1 for case in out if case["android"] and case["android"]["status"] == "passed"),
                            "android_run": sum(1 for case in out if case["android"])},
                "cases": out}
    text = json.dumps(evidence, indent=1, ensure_ascii=False)
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
    page = (SITE / "tools" / "aether-results-intro.html").read_text()
    for key, value in run.items():
        page = page.replace("{" + key + "}", e(value))
    for key in ("iphone_passed", "iphone_run", "android_passed", "android_run"):
        page = page.replace("{" + key + "}", str(summary[key]))
    page = page.replace("{sections}", "\n\n".join(sections))
    (SITE / "aether" / "results.html").write_text(page)
    print("wrote aether/results.html")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("extract")
    one.add_argument("--cases", nargs="+", required=True, help="the iPhone's case lists (their rows and settings)")
    one.add_argument("--ios", nargs="*", default=[])
    one.add_argument("--android", nargs="*", default=[])
    one.add_argument("--replace", nargs="*", default=[], help="real=placeholder pairs")
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
