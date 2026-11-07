#!/usr/bin/env python3
"""Turns the SSL VPN (AnyConnect) test runs of both phones into sslvpn/results.html (after softether_results.py).

  extract  reads the iPhone runner's and the Android runners' results.json files with the case list and writes one
           sanitized evidence file; a later file's run of a case replaces an earlier one
  render   writes sslvpn/results.html from an evidence file
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from softether_results import e, hello_fact, hello_length, lifecycle_words  # noqa: E402
from sstp_results import FAILED, NOT_RUN, VERIFIED, Sanitizer, merged  # noqa: E402
from waterwall_scenarios import LOCAL_PATH, PUBLIC_IPV4  # noqa: E402

SITE = Path(__file__).resolve().parent.parent
GROUPS = [
    ("Transfers over DTLS and TLS", lambda i: re.match(r"ocv-(pass|tls-only)", i)),
    ("Logins", lambda i: re.match(r"ocv-(cert|wrong)", i)),
    ("Certificate check, names and ports", lambda i: re.match(r"ocv-(verify|allow|port|host)", i)),
    ("Server Type", lambda i: i.startswith("ocv-type")),
    ("Server settings", lambda i: re.match(r"ocv-(server|split|path)", i)),
    ("TLS Fragmentation", lambda i: i.startswith("ocv-frag")),
    ("Log levels", lambda i: i.startswith("ocv-log")),
    ("Sleep, lost connections, network switch and Retry Times", lambda i: "-life-" in i or i.startswith("ocv-retry")),
]
TRAFFIC = {"download": "download", "upload": "upload", "full-duplex": "download and upload at once", "none": "connect only"}
SERVER_CHANGES = {
    "ocv-tls-only-download": "server: UDP 443 blocked (no DTLS)", "ocv-tls-only-full-duplex": "server: UDP 443 blocked (no DTLS)",
    "ocv-server-tls13": "server: TLS 1.3 allowed in tls-priorities", "ocv-server-dtls-no-psk": "server: dtls-psk = false",
    "ocv-server-compression": "server: compression = true", "ocv-server-ban": "server: max-ban-score = 1",
    "ocv-server-camouflage": "server: camouflage on, with a secret; Path empty",
    "ocv-path-camouflage": "server: camouflage on; Path ?secret",
    "ocv-path-camouflage-wrong-secret": "server: camouflage on; Path with a wrong secret",
    "ocv-path-camouflage-log": "server: camouflage on; Path ?secret; the log checked for the secret",
    "ocv-path-camouflage-reset-resume": "server: camouflage on; Path ?secret; the server resets the TCP connection, Auto Reconnect on",
    "ocv-server-tls11-only": "a server on another port that offers only TLS 1.1",
    "ocv-split-group": "a user of the split-tunnel group", "ocv-retry-before-connect": "server: ocserv stopped",
}


def settings_of(case, clean):
    """What the case sets, in the profile editor's words."""
    profile = case["profile"]
    items = []
    server = profile.get("server", "")
    if server.replace(".", "").isdigit():
        items.append("Server is the server's IP address")
    elif server.startswith("no-such-host"):
        items.append("Server is a name that does not exist")
    kind = profile.get("ocProtocol", "anyconnect")
    if kind != "anyconnect":
        items.append("Server Type " + {"f5": "F5 BIG-IP", "gp": "Palo Alto GP"}[kind] + " (the server speaks AnyConnect)")
    if "cert" in case:
        items.append("Method Certificate" + (" (a certificate from another authority)" if "rogue" in case["cert"]["p12"] else ""))
        if profile.get("username") != "oc-cert1":
            items.append("Username of another user")
    elif profile.get("authMethod") == "certificate":
        items.append("Method Certificate without a certificate")
    if profile.get("username") == "oc-nouser":
        items.append("a user the server does not have")
    if case.get("password_suffix"):
        items.append("wrong password")
    if profile.get("TLS"):
        items.append("TLS Server Verification off")
    port = profile.get("port", "443")
    if port != "443":
        items.append(f"Port {port}" + {"8443": " (redirected to 443 on the server)", "22": " (the server's SSH answers it)",
                                       "4443": "" if case["id"] == "ocv-server-tls11-only" else " (nothing listens on it)"}.get(port, ""))
    if case["id"] in SERVER_CHANGES:
        items.append(SERVER_CHANGES[case["id"]])
    if "tlsFragMode" in profile:
        mode = profile["tlsFragMode"]
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


def session_facts(result, clean):
    """What ocserv's occtl said about the phone's session, when the case read it."""
    text = "\n".join(result.get("marker_outputs") or [])
    if "Username:" not in text:
        return []
    facts = []
    tls = re.search(r"TLS ciphersuite: \((TLS1\.\d)\)", text)
    if tls:
        facts.append(tls[1].replace("TLS", "TLS "))
    dtls = re.search(r"DTLS cipher: \((DTLS1\.\d)\)-\(([^)]+)\)", text)
    facts.append(f"data over {dtls[1].replace('DTLS', 'DTLS ')} ({dtls[2]})" if dtls else "data over TLS (no DTLS)")
    routes = re.search(r"Routes: (.+)", text)
    if routes and "defaultroute" not in routes[1]:
        facts.append("routes " + clean.text(routes[1].strip()))
    user = re.search(r"Username: (\S+)", text)
    if user and user[1] == "oc-cert1":
        facts.append("logged in as the certificate's user")
    return facts


LOG_WORDS = {"OpenConnect connecting to": "the connect line", "OpenConnect: session established": "the session line",
             "[oc] Connected to": "libopenconnect's progress lines", "OpenConnect: routes through the tunnel: ": "the routes line",
             "OpenConnect: routes through the tunnel": "the routes line", "routes through the tunnel: all;": "a full-tunnel routes line",
             "[oc] X-CSTP-": "the server's tunnel headers", "[oc] X-CSTP-Address": "the server's tunnel headers",
             "Set-Cookie: webvpn=<elided>": "the session cookie, hidden", "Set-Cookie: webvpncontext=<elided>": "the context cookie, hidden",
             "SSL_KEYLOG": "TLS secrets", "CLIENT_RANDOM": "TLS secrets", "X-DTLS-Master-Secret": "the DTLS secret",
             "OpenConnect: closing with reason: Authentication failed": "the reason the app closed the connection",
             "characters>": "the Path's secret as its length", "srp-camouflage-test": "the Path's secret"}


def log_facts(result):
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


def ios_result(case, result, clean, egress, hello=None):
    if result is None:
        return None
    entry = {"status": result.get("status"), "facts": session_facts(result, clean)}
    if result.get("configuration") == "Release":
        entry["facts"].insert(0, "Release build")
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
    sent = hello_fact(result, hello)
    if sent:
        entry["facts"].append(sent)
    moves = case.get("traffic", "download") != "none" and case.get("expect") != "fail"
    entry["through_server"] = egress in (result.get("stress_sources") or {}) if moves else None
    return entry


def android_result(case, result, clean, hello=None):
    if result is None:
        return None
    entry = {"status": "passed" if result.get("passed") else "failed", "transfer_s": result.get("transfer_s"),
             "facts": session_facts(result, clean)}
    if result.get("state") == "Declined":
        entry["message"] = "the certificate warning was declined"
    elif result.get("message"):
        entry["message"] = clean.text(result["message"])
    if result.get("error"):
        entry["error"] = clean.text(result["error"])
    if result.get("lifecycle"):
        entry["lifecycle"] = [clean.text(item) for item in result["lifecycle"]]
    entry["facts"].extend(log_facts(result))
    sent = hello_fact(result, hello)
    if sent:
        entry["facts"].append(sent)
    return entry


def extract(args):
    clean = Sanitizer(dict(pair.split("=", 1) for pair in args.replace))
    cases = [case for path in args.cases for case in json.loads(Path(path).read_text())]
    ios = merged(args.ios)
    android = merged(args.android)
    # the Android lifecycle tool names its cases android-life-*; they stand beside the iPhone's ocv-life-* rows
    life = {"ocv-life-sleep-modes": ["android-life-sleep-stay", "android-life-sleep-pause", "android-life-sleep-off-reconnects",
                                     "android-life-sleep-off-ends"],
            "ocv-life-server-ends-reconnect": ["android-life-peer-drop-reconnect"],
            "ocv-life-server-ends-no-reconnect": ["android-life-peer-drop-no-reconnect"],
            "ocv-life-reset-resume": ["android-life-reset-resume"],
            "ocv-life-reset-no-reconnect": ["android-life-reset-no-reconnect"],
            "ocv-life-path-switch": ["android-life-wifi-switch"],
            "ocv-life-retry-exhausted": ["android-life-retry-exhausted"],
            "ocv-life-outage-reconnect": ["android-life-outage-reconnect"],
            "ocv-path-camouflage-reset-resume": ["android-life-camouflage-reset-resume"]}
    hello_ios = hello_length(ios.get("ocv-frag-auto-capture"))
    hello_android = hello_length(android.get("ocv-frag-auto-capture"))
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
    # 1.1.1.1 and 8.8.8.8 are the DNS servers sslvpn/server.html gives the phones, in the split group's routes too
    leaks = sorted(set(PUBLIC_IPV4.findall(text)) - {"1.1.1.1", "8.8.8.8"})
    if leaks:
        sys.exit(f"Public addresses left in the evidence: {leaks}")
    if LOCAL_PATH.search(text):
        sys.exit("A local path is left in the evidence")
    Path(args.output).write_text(text + "\n")
    print(f"{len(out)} cases; iPhone {evidence['summary']['iphone_passed']}/{evidence['summary']['iphone_run']}, "
          f"Android {evidence['summary']['android_passed']}/{evidence['summary']['android_run']}")


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
    page = (SITE / "tools" / "sslvpn-results-intro.html").read_text()
    for key, value in {"date": run["date"], "iphone": run["iphone"], "android": run["android"], "app": run["app"], "server": run["server"]}.items():
        page = page.replace("{" + key + "}", e(value))
    for key in ("iphone_passed", "iphone_run", "android_passed", "android_run"):
        page = page.replace("{" + key + "}", str(summary[key]))
    page = page.replace("{sections}", "\n\n".join(sections))
    (SITE / "sslvpn" / "results.html").write_text(page)
    print("wrote sslvpn/results.html")


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
