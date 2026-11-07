#!/usr/bin/env python3
"""Turns the SSTP test runs of both phones into sstp/results.html.

  extract  reads the iPhone runner's and the Android runner's results.json files with the case list and writes one
           sanitized evidence file; a later file's run of a case replaces an earlier one
  render   writes sstp/results.html from evidence files
"""
import argparse
import html
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from waterwall_scenarios import LOCAL_PATH, PUBLIC_IPV4

SITE = Path(__file__).resolve().parent.parent
VERIFIED = '<span class="status verified">VERIFIED — TESTED SUCCESSFULLY</span>'
FAILED = '<span class="status failed">TESTED — FAILED</span>'
NOT_RUN = '<span class="status planned">NOT VERIFIED</span>'

SERVERS = {
    "mt": "MikroTik RouterOS 7.25", "sstp": "MikroTik RouterOS 7.25", "android": "MikroTik RouterOS 7.25",
    "se": "SoftEther VPN Server 4.44",
    "win2019": "Windows Server 2019", "win2022": "Windows Server 2022", "win2025": "Windows Server 2025 with FreeRADIUS",
}
ORDER = ["MikroTik RouterOS 7.25", "SoftEther VPN Server 4.44", "Windows Server 2019", "Windows Server 2022",
         "Windows Server 2025 with FreeRADIUS"]
TTLS = {1: "EAP", 2: "PAP", 3: "CHAP", 4: "MSCHAPv2"}


class Sanitizer:
    def __init__(self, replacements):
        self.replacements = sorted(replacements.items(), key=lambda item: -len(item[0]))

    def text(self, value):
        text = str(value)
        for real, placeholder in self.replacements:
            text = text.replace(real, placeholder)
        return LOCAL_PATH.sub("<LOCAL_PATH>", text)


def merged(paths):
    cases = {}
    for path in paths:
        data = json.loads(Path(path).read_text())
        for case in data["cases"] if isinstance(data, dict) else data:
            cases[case["id"]] = case
    return cases


def settings_of(case, clean):
    """What the case sets, in the profile editor's words."""
    profile = case["profile"]
    items = []
    if profile.get("server", "").replace(".", "").isdigit():
        items.append("Host is the server's IP address")
    if "cert" in case:
        items.append("Method Certificate" + (" from another CA" if "rogue" in case["cert"]["p12"] else ""))
    if profile.get("MSCHAP2", True) is False:
        items.append("MS-CHAPv2 off")
    if profile.get("allowLegacyPapChap"):
        items.append("PAP / CHAP on")
    eap = profile.get("eapConfig", {})
    if eap.get("eap_mschapv2_enabled"):
        items.append("EAP-MSCHAPv2")
    if eap.get("peap_enabled"):
        items.append("PEAP" + (" with Require Crypto Binding" if eap.get("peap_require_crypto_binding") else ""))
    if eap.get("ttls_inner_method"):
        items.append(f"EAP-TTLS with {TTLS[eap['ttls_inner_method']]}")
    if eap.get("teap_enabled"):
        items.append("TEAP")
    if eap.get("identity_privacy_enabled"):
        items.append("Identity Privacy")
    if "eap_tls13_enabled" in eap:
        items.append("EAP TLS 1.3 " + ("on, TLS 1.0 & 1.1 off" if eap["eap_tls13_enabled"] else "off, TLS 1.0 & 1.1 allowed"))
    if profile.get("TLS"):
        items.append("Allow Untrusted Certificate")
    if profile.get("disableLegacyOuterTls"):
        items.append("Disable TLS 1.0 & 1.1")
    if profile.get("customSniEnabled") is not None and "customSni" in profile:
        sni = clean.text(profile["customSni"])
        items.append(f"Custom SNI {sni}" if profile["customSniEnabled"] else f"Custom SNI off (with {sni} typed)")
    mode = profile.get("tlsFragMode", 0)
    if mode == 1:
        items.append("TLS Fragmentation Auto")
    elif mode == 2:
        items.append(f"TLS Fragmentation Manual {profile.get('tlsFragFirst') or 32}/{profile.get('tlsFragFollowing') or 256}")
    proxy = profile.get("proxyMode", 0)
    if proxy == 1:
        port = profile.get("proxyPort")
        kind = {"3128": "manual proxy", "3129": "manual proxy with username and password", "3999": "manual proxy that is not there"}.get(port, "manual proxy")
        if case.get("env_secrets", {}).get("SRP_LIVE_PROXY_PASSWORD", {}).get("suffix"):
            kind = "manual proxy with a wrong password"
        items.append(kind)
    elif proxy == 2:
        items.append("PAC proxy" + (" with username and password" if profile.get("proxyUsername") else ""))
    if profile.get("logLevel") == 1:
        items.append("Log Level Expert")
    elif profile.get("logLevel") == 2:
        items.append("Log Level Debug")
    elif profile.get("logLevel") == 0:
        items.append("Log Level Normal")
    if "-life-" in case["id"]:
        # the lifecycle cases are about these two settings; elsewhere the test profiles just turn Auto Reconnect off
        if "onSleep" in profile:
            items.append("On Sleep " + ["Off", "Pause", "Stay"][profile["onSleep"]])
        if "sleep-modes" in case["id"]:
            items.append("On Sleep Stay, Pause and Off, and Off with Auto Reconnect off")
        else:
            items.append("Auto Reconnect " + ("on" if profile.get("autoReconnect") else "off"))
    if profile.get("retryTimes"):
        items.append(f"Retry Times {profile['retryTimes']}")
    if case.get("password_suffix"):
        items.append("wrong password")
    if profile.get("port") not in (None, "443"):
        items.append(f"Port {profile['port']}")
    if profile.get("username", "").startswith("radius"):
        items.append("RADIUS user")
    for command in case.get("router_before", []):
        items.append("router: " + command.split(" set ", 1)[-1])
    if "securenat" in case["id"]:
        items.append("SoftEther SecureNAT")
    return items or ["defaults"]


def lifecycle_words(note):
    """The iPhone lifecycle test's log words in the profile editor's words."""
    note = re.sub(r"sleep mode (\d)", lambda m: "On Sleep " + ["Off", "Pause", "Stay"][int(m.group(1))], note)
    note = re.sub(r"auto reconnect (\d)", lambda m: "Auto Reconnect " + ["off", "on"][int(m.group(1))], note)
    note = re.sub(r"recovered=1 after ([\d.]+) seconds", r"connected again after \1 s", note)
    note = re.sub(r"disconnected=1 after ([\d.]+) seconds, error: ", r"ended after \1 s with: ", note)
    return note.replace("peer-drop: ", "the server dropped the session: ").replace("retry-exhausted: ", "the SSTP server was turned off: ")


TRAFFIC = {"download": "download", "upload": "upload", "full-duplex": "download and upload at once", "none": "connect only"}


def ios_result(case, result, clean, egress):
    if result is None:
        return None
    entry = {"status": result.get("status"), "configuration": result.get("configuration"), "seconds": result.get("seconds")}
    if result.get("download"):
        entry["download_mbps"] = result["download"]["mbps"]
        entry["seconds_measured"] = result["download"]["seconds"]
    if result.get("full_duplex"):
        entry["download_mbps"] = result["full_duplex"]["download_mbps"]
        entry["upload_mbps"] = result["full_duplex"]["upload_mbps"]
        entry["seconds_measured"] = result["full_duplex"]["seconds"]
        entry["errors"] = clean.text(result["full_duplex"]["errors"])
    if result.get("expected_failure"):
        entry["message"] = clean.text(result["expected_failure"]["message"])
    if result.get("lifecycle"):
        entry["lifecycle"] = [clean.text(lifecycle_words(": ".join(item))) for item in result["lifecycle"]]
    # the test server logged the VPN server's own address for this case's requests
    moves = case.get("traffic", "download") != "none" and case.get("expect") != "fail"
    entry["through_server"] = egress.get(case["profile"].get("server")) in (result.get("stress_sources") or {}) if moves else None
    return entry


def android_result(case, result, clean):
    if result is None:
        return None
    entry = {"status": "passed" if result.get("passed") else "failed", "state": result.get("state"), "connect_s": result.get("connect_s"),
             "transfer_s": result.get("transfer_s")}
    if result.get("message"):
        entry["message"] = clean.text(result["message"])
    if result.get("error"):
        entry["error"] = clean.text(result["error"])
    if result.get("sources") is not None:
        entry["through_server"] = bool(result["sources"])
    if result.get("lifecycle"):
        entry["lifecycle"] = [clean.text(item) for item in result["lifecycle"]]
    return entry


def extract(args):
    replacements = {}
    for pair in args.replace:
        real, placeholder = pair.split("=", 1)
        replacements[real] = placeholder
    clean = Sanitizer(replacements)
    cases = json.loads(Path(args.cases).read_text())
    extra = json.loads(Path(args.extra_cases).read_text()) if args.extra_cases else []
    egress = json.loads(Path(args.egress).read_text()) if args.egress else {}
    ios = merged(args.ios)
    android = merged(args.android)
    out = []
    for case in cases + extra:
        if case["id"] not in ios and case["id"] not in android:
            continue
        out.append({"id": case["id"], "server": SERVERS[case["id"].split("-")[0]], "settings": settings_of(case, clean),
                    "traffic": TRAFFIC[case.get("traffic", "download")] + (f", {case.get('duration', 60)} s" if case.get("traffic", "download") != "none" and case.get("expect") != "fail" else ""),
                    "expect": case.get("expect", "connect"), "iphone": ios_result(case, ios.get(case["id"]), clean, egress),
                    "android": android_result(case, android.get(case["id"]), clean)})
    evidence = {"run": {"date": args.date, "iphone": args.iphone, "android": args.android_device, "app": args.app,
                        "servers": args.servers, "reruns": args.reruns},
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


def cell(entry, expect, phone):
    if entry is None:
        return NOT_RUN
    status = VERIFIED if entry["status"] == "passed" else FAILED
    details = []
    if phone == "iphone":
        if entry.get("upload_mbps") is not None and entry.get("download_mbps") is not None:
            details.append(f"down {entry['download_mbps']} / up {entry['upload_mbps']} Mbit/s")
        elif entry.get("download_mbps") is not None:
            details.append(f"{entry['download_mbps']} Mbit/s")
    else:
        if entry.get("transfer_s") is not None:
            details.append(f"transfer {entry['transfer_s']} s")
    if entry.get("message"):
        details.append(f"<em>{e(entry['message'])}</em>")
    if entry.get("lifecycle"):
        details.extend(e(item) for item in entry["lifecycle"])
    return status + ("<br>" + "<br>".join(details) if details else "")


def render(args):
    evidences = [json.loads(Path(path).read_text()) for path in args.evidence]
    cases = [case for evidence in evidences for case in evidence["cases"]]
    run = evidences[0]["run"]
    summary = evidences[0]["summary"]
    sections = []
    for server in ORDER:
        rows = [case for case in cases if case["server"] == server]
        if not rows:
            continue
        body = []
        for case in rows:
            expect = "connect" if case["expect"] == "connect" else "refused"
            body.append(f"<tr><td><code>{e(case['id'])}</code></td><td>{e('; '.join(case['settings']))}</td><td>{e(case['traffic'])}</td>"
                        f"<td>{expect}</td><td>{cell(case['iphone'], case['expect'], 'iphone')}</td>"
                        f"<td>{cell(case['android'], case['expect'], 'android')}</td></tr>")
        anchor = re.sub(r"[^a-z0-9]+", "-", server.lower()).strip("-")
        sections.append(f'<h2 id="{anchor}">{e(server)}</h2>\n<div class="table-scroll"><table>\n'
                        '<thead><tr><th>Case</th><th>Settings</th><th>Traffic</th><th>Expected</th><th>iPhone</th><th>Android</th></tr></thead>\n'
                        "<tbody>\n" + "\n".join(body) + "\n</tbody></table></div>")
    template = (SITE / "tools" / "sstp-results-intro.html").read_text()
    page = template.replace("{date}", e(run["date"])).replace("{iphone}", e(run["iphone"])).replace("{android}", e(run["android"])) \
        .replace("{app}", e(run["app"])).replace("{servers}", e(run["servers"])).replace("{reruns}", e(run.get("reruns", ""))) \
        .replace("{iphone_passed}", str(summary["iphone_passed"])).replace("{iphone_run}", str(summary["iphone_run"])) \
        .replace("{android_passed}", str(summary["android_passed"])).replace("{android_run}", str(summary["android_run"])) \
        .replace("{sections}", "\n\n".join(sections))
    (SITE / "sstp" / "results.html").write_text(page)
    print("wrote sstp/results.html")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("extract")
    one.add_argument("--cases", required=True)
    one.add_argument("--extra-cases")
    one.add_argument("--ios", nargs="*", default=[])
    one.add_argument("--android", nargs="*", default=[])
    one.add_argument("--replace", nargs="*", default=[], help="real=placeholder pairs")
    one.add_argument("--date", required=True)
    one.add_argument("--iphone", required=True)
    one.add_argument("--android-device", required=True)
    one.add_argument("--app", required=True)
    one.add_argument("--servers", required=True)
    one.add_argument("--output", required=True)
    one.add_argument("--egress", help="JSON map of each server host to the address its clients' traffic leaves from")
    one.add_argument("--reruns", default="", help="a sentence on which cases ran again on which build")
    two = sub.add_parser("render")
    two.add_argument("--evidence", nargs="+", required=True)
    args = parser.parse_args()
    extract(args) if args.command == "extract" else render(args)


if __name__ == "__main__":
    main()
