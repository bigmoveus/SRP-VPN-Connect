#!/usr/bin/env python3
"""Turns the SoftEther test runs of both phones into softether/results.html.

  extract  reads the iPhone runner's and the Android runners' results.json files with the case list and writes one
           sanitized evidence file; a later file's run of a case replaces an earlier one
  render   writes softether/results.html from an evidence file
"""
import argparse
import html
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sstp_results import FAILED, NOT_RUN, VERIFIED, Sanitizer, merged  # noqa: E402
from waterwall_scenarios import LOCAL_PATH, PUBLIC_IPV4  # noqa: E402

SITE = Path(__file__).resolve().parent.parent
METHODS = {"standardPassword": "Standard Password", "radiusNT": "RADIUS / NT Domain", "certificate": "Certificate", "anonymous": "Anonymous"}
GROUPS = [
    ("Logins and hubs", lambda i: re.match(r"sev-(pass|radius|anon|cert|hub|wrong)", i)),
    ("Certificate check, Hostname and ports", lambda i: re.match(r"sev-(verify|hostname|allow|port)", i)),
    ("Connections and UDP acceleration", lambda i: re.match(r"sev-(conns|udp)", i)),
    ("NAT traversal", lambda i: i.startswith("sev-natt")),
    ("Proxies and PAC files", lambda i: re.match(r"sev-(proxy|pac)", i)),
    ("TLS Fragmentation", lambda i: i.startswith("sev-frag")),
    ("Log levels", lambda i: i.startswith("sev-log")),
    ("Sleep, lost connections and Retry Times", lambda i: "-life-" in i),
]
TRAFFIC = {"download": "download", "upload": "upload", "full-duplex": "download and upload at once", "none": "connect only"}


def settings_of(case, clean):
    """What the case sets, in the profile editor's words."""
    profile = case["profile"]
    items = []
    if profile.get("server", "").replace(".", "").isdigit():
        items.append("Server is the server's IP address")
    if profile.get("hostnameOverride"):
        name = profile["hostnameOverride"]
        items.append("Hostname " + ("a name the certificate is not for" if name.startswith("wrong.") else clean.text(name)))
    method = profile.get("seAuthMethod", "standardPassword")
    if method != "standardPassword" or "cert" in case:
        text = "Method " + METHODS[method]
        if "cert" in case:
            text += " (a certificate from another authority)" if "rogue" in case["cert"]["p12"] else \
                (" (signed certificate user)" if "cert1" in case["cert"]["p12"] else " (individual certificate user)")
        elif method == "certificate":
            text += " without a certificate"
        items.append(text)
    user = profile.get("username", "")
    if user.startswith("se-radius") and method != "radiusNT":
        items.append("RADIUS user")
    if user.startswith("se-pass") and method == "anonymous":
        items.append("password user")
    if profile.get("hubName", "DEFAULT") != "DEFAULT":
        items.append("Virtual Hub " + profile["hubName"])
    if case.get("password_suffix"):
        items.append("wrong password")
    if profile.get("TLS"):
        items.append("TLS Server Verification off")
    if profile.get("port") not in (None, "443"):
        items.append(f"Port {profile['port']}" + {"5557": " (nothing listens on it)",
                                                  "22": " (the server's SSH answers it)"}.get(profile["port"], ""))
    if profile.get("seConnections"):
        items.append(f"Connections {profile['seConnections']}")
    if profile.get("seUdpAcceleration"):
        items.append("UDP acceleration on")
    if "seNatTraversal" in profile:
        hint = profile.get("seNatTHint")
        items.append("NAT-T " + ("on" if profile["seNatTraversal"] else "off") +
                     (", hint " + ("the server's own address" if hint and not hint.startswith("10.") else "an address no server has") if hint else ""))
    proxy = profile.get("proxyMode", 0)
    if proxy == 1:
        port = profile.get("proxyPort")
        kind = {"3128": "HTTP proxy", "3129": "HTTP proxy with username and password", "1080": "SOCKS5 proxy",
                "1081": "SOCKS5 proxy with username and password", "3999": "proxy port nothing listens on"}.get(port, "manual proxy")
        if case.get("env_secrets", {}).get("SRP_LIVE_PROXY_PASSWORD", {}).get("suffix"):
            kind = kind.replace("with username and password", "with a wrong password")
        items.append(kind)
    elif proxy == 2:
        name = profile.get("pacURL", "").rsplit("/", 1)[-1]
        answer = {"http.pac": "PROXY", "http-auth.pac": "PROXY with username and password", "socks5.pac": "SOCKS5",
                  "socks.pac": "SOCKS", "socks5-auth.pac": "SOCKS5 with username and password", "direct.pac": "DIRECT",
                  "fallback.pac": "an unreachable PROXY, then a working one", "missing.pac": "a PAC URL that answers 404"}.get(name, name)
        items.append("PAC file: " + answer)
    mode = profile.get("tlsFragMode", 0)
    if "tlsFragMode" in profile:
        items.append({0: "TLS Fragmentation Off", 1: "TLS Fragmentation Auto"}.get(mode) or
                     f"TLS Fragmentation Manual {profile.get('tlsFragFirst') or 32}/{profile.get('tlsFragFollowing') or 256}")
    if "logLevel" in profile:
        items.append("Log Level " + ["Normal", "Expert", "Debug"][profile["logLevel"]])
    if "-life-" in case["id"]:
        if "sleep-modes" in case["id"]:
            items.append("On Sleep Stay, Pause and Off, and Off with Auto Reconnect off")
        else:
            items.append("Auto Reconnect " + ("on" if profile.get("autoReconnect") else "off"))
    if profile.get("retryTimes"):
        items.append(f"Retry Times {profile['retryTimes']}")
    return items or ["defaults"]


def lifecycle_words(note):
    """The iPhone lifecycle test's log words in the profile editor's words."""
    note = re.sub(r"sleep mode (\d)", lambda m: "On Sleep " + ["Off", "Pause", "Stay"][int(m.group(1))], note)
    note = re.sub(r"auto reconnect (\d)", lambda m: "Auto Reconnect " + ["off", "on"][int(m.group(1))], note)
    note = re.sub(r"recovered=1 after ([\d.]+) seconds", r"connected again after \1 s", note)
    note = re.sub(r"disconnected=1 after ([\d.]+) seconds, error: ", r"ended after \1 s with: ", note)
    return note.replace("peer-drop: ", "").replace("retry-exhausted: ", "the server was stopped: ")


def session_facts(result):
    """What the server's SessionGet said about the session, when the case read it."""
    text = "\n".join(result.get("marker_outputs") or [])
    facts = []
    connections = re.search(r"Number of TCP Connections\s*\|(\d+)", text)
    # read right after the connect, the count can still be 0: it says something only once connections are up
    if connections and int(connections[1]) > 0:
        facts.append(f"{connections[1]} TCP connections")
    if re.search(r"UDP Acceleration is Active\s*\|Yes", text):
        facts.append("UDP acceleration active")
    if "VPN over UDP with NAT-T" in text:
        facts.append("over NAT-T")
    return facts


LOG_WORDS = {"SoftEther connecting to": "the connect line", "SoftEther: session established": "the session line",
             "SoftEther: negotiation": "the connection steps", "[se] DHCP bound": "the adapter's DHCP line",
             "SessionConnect() Started": "the core's own lines", "SSL_KEYLOG": "TLS secrets", "_SECRET ": "TLS secrets",
             "CLIENT_RANDOM": "TLS secrets"}


def log_facts(result):
    """What a log-level case found in the connection log it read back."""
    check = (result or {}).get("log_check") or {}
    if not check:
        return []
    def words(prefix, value):
        return list(dict.fromkeys(LOG_WORDS[key[len(prefix):]] for key, ok in check.items() if key.startswith(prefix) and ok == value))
    facts = []
    if not check.get("log fetched", True):
        facts.append("no log came back")
    for label, prefix, value in (("in the log", "has ", True), ("not in the log", "lacks ", True),
                                 ("missing from the log", "has ", False), ("also in the log", "lacks ", False)):
        if words(prefix, value):
            facts.append(f"{label}: " + ", ".join(words(prefix, value)))
    return facts


def segments_of(result):
    """The sizes of the first client segments to TCP 443 that the server recorded (TLS Fragmentation cases)."""
    for output in (result or {}).get("after_outputs") or []:
        sizes = [int(size) for size in output.split() if size.isdigit()]
        if sizes:
            return sizes
    return None


def fragments(result, hello):
    """The segments that carried the ClientHello: the first ones up to its length, which the case with
    TLS Fragmentation Off shows as its first segment."""
    sizes = segments_of(result)
    if not sizes:
        return None
    if not hello:
        return sizes[:1]
    taken, total = [], 0
    for size in sizes:
        taken.append(size)
        total += size
        if total >= hello:
            break
    return taken


def ios_result(case, result, clean, egress, hello=None):
    if result is None:
        return None
    entry = {"status": result.get("status"), "facts": session_facts(result)}
    if result.get("download"):
        entry["download_mbps"] = result["download"]["mbps"]
    if result.get("full_duplex"):
        entry["download_mbps"] = result["full_duplex"]["download_mbps"]
        entry["upload_mbps"] = result["full_duplex"]["upload_mbps"]
    if result.get("expected_failure"):
        message = result["expected_failure"]["message"]
        entry["message"] = "the certificate warning was declined" if result.get("untrusted_prompt") == ["declined"] else clean.text(message)
    if result.get("untrusted_prompt") == ["accepted"]:
        entry["facts"].append("the certificate warning was accepted")
    if result.get("lifecycle"):
        entry["lifecycle"] = [clean.text(lifecycle_words(": ".join(item))) for item in result["lifecycle"]]
    entry["facts"].extend(log_facts(result))
    segments = fragments(result, hello)
    if segments:
        entry["facts"].append("ClientHello sent as " + " + ".join(map(str, segments)) + " bytes")
    moves = case.get("traffic", "download") != "none" and case.get("expect") != "fail"
    entry["through_server"] = egress in (result.get("stress_sources") or {}) if moves else None
    return entry


def android_result(case, result, clean, hello=None):
    if result is None:
        return None
    entry = {"status": "passed" if result.get("passed") else "failed", "transfer_s": result.get("transfer_s"),
             "facts": session_facts(result)}
    if result.get("state") == "Declined":
        entry["message"] = "the certificate warning was declined"
    elif result.get("message"):
        entry["message"] = clean.text(result["message"])
    if result.get("error"):
        entry["error"] = clean.text(result["error"])
    if result.get("lifecycle"):
        entry["lifecycle"] = [clean.text(item) for item in result["lifecycle"]]
    entry["facts"].extend(log_facts(result))
    segments = fragments(result, hello)
    if segments:
        entry["facts"].append("ClientHello sent as " + " + ".join(map(str, segments)) + " bytes")
    return entry


def extract(args):
    replacements = dict(pair.split("=", 1) for pair in args.replace)
    clean = Sanitizer(replacements)
    cases = json.loads(Path(args.cases).read_text())
    ios = merged(args.ios)
    android = merged(args.android)
    # the Android lifecycle tool names its cases android-life-*; they stand beside the iPhone's sev-life-* rows
    life = {"sev-life-sleep-modes": ["android-life-sleep-stay", "android-life-sleep-pause", "android-life-sleep-off-reconnects", "android-life-sleep-off-ends"],
            "sev-life-peer-drop-reconnect": ["android-life-peer-drop-reconnect"],
            "sev-life-peer-drop-no-reconnect": ["android-life-peer-drop-no-reconnect"],
            "sev-life-retry-exhausted": ["android-life-retry-exhausted"],
            "sev-life-outage-reconnect": ["android-life-outage-reconnect"]}
    # each phone's ClientHello length: the first segment of the case without TLS Fragmentation
    hello_ios = (segments_of(ios.get("sev-frag-off-capture")) or [None])[0]
    hello_android = (segments_of(android.get("sev-frag-off-capture")) or [None])[0]
    out = []
    for case in cases:
        if case["id"] not in ios and case["id"] not in android and not any(name in android for name in life.get(case["id"], [])):
            continue
        droid = android.get(case["id"])
        if case["id"] in life:
            parts = [android[name] for name in life[case["id"]] if name in android]
            droid = {"passed": all(part.get("passed") for part in parts),
                     "lifecycle": [note for part in parts for note in (part.get("lifecycle") or [part.get("error", "")])]} if parts else None
        traffic = case.get("traffic", "download")
        out.append({"id": case["id"], "settings": settings_of(case, clean),
                    "traffic": TRAFFIC[traffic] + (f", {case.get('duration', 60)} s" if traffic != "none" and case.get("expect") != "fail" else ""),
                    "expect": case.get("expect", "connect"), "iphone": ios_result(case, ios.get(case["id"]), clean, args.egress, hello_ios),
                    "android": android_result(case, droid, clean, hello_android)})
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


def e(value):
    return html.escape(str(value))


def cell(entry, phone):
    if entry is None:
        return NOT_RUN
    status = VERIFIED if entry["status"] == "passed" else FAILED
    details = []
    if phone == "iphone":
        if entry.get("upload_mbps") is not None and entry.get("download_mbps") is not None:
            details.append(f"down {entry['download_mbps']} / up {entry['upload_mbps']} Mbit/s")
        elif entry.get("download_mbps") is not None:
            details.append(f"{entry['download_mbps']} Mbit/s")
    elif entry.get("transfer_s") is not None:
        details.append(f"transfer {entry['transfer_s']} s")
    details.extend(e(fact) for fact in entry.get("facts", []))
    if entry.get("message"):
        details.append(f"<em>{e(entry['message'])}</em>")
    if entry.get("lifecycle"):
        details.extend(e(item) for item in entry["lifecycle"])
    if entry.get("error"):
        details.append(e(entry["error"]))
    return status + ("<br>" + "<br>".join(details) if details else "")


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
    template = (SITE / "tools" / "softether-results-intro.html").read_text()
    page = template
    for key, value in {"date": run["date"], "iphone": run["iphone"], "android": run["android"], "app": run["app"], "server": run["server"]}.items():
        page = page.replace("{" + key + "}", e(value))
    for key in ("iphone_passed", "iphone_run", "android_passed", "android_run"):
        page = page.replace("{" + key + "}", str(summary[key]))
    page = page.replace("{sections}", "\n\n".join(sections))
    (SITE / "softether" / "results.html").write_text(page)
    print("wrote softether/results.html")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("extract")
    one.add_argument("--cases", required=True)
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
