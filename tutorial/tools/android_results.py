#!/usr/bin/env python3
"""Turns the Android test runs into the results on waterwall/android.html.

  extract  reads the results.json of a production run and a lifecycle run and writes a sanitized evidence file
  render   writes the block between android:begin and android:end from that evidence file
"""
import argparse
import html
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from waterwall_scenarios import LOCAL_PATH, PUBLIC_IPV4, title_of

SITE = Path(__file__).resolve().parent.parent
VERIFIED = '<span class="status verified">VERIFIED — TESTED SUCCESSFULLY</span>'
FAILED = '<span class="status failed">TESTED — FAILED</span>'


def clean(text, server_host):
    text = text.replace(server_host, "<SERVER_HOST>")
    text = re.sub(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "<UUID>", text)
    return LOCAL_PATH.sub("<LOCAL_PATH>", text)


def merged(paths):
    """The cases of several results files; a later file's run of a case replaces an earlier one."""
    files = [json.loads(Path(path).read_text()) for path in paths]
    return files[0], list({case["id"]: case for data in files for case in data["cases"]}.values())


def extract(args):
    production, chain_cases = merged(args.production)
    _, check_cases = merged(args.lifecycle)
    chains = [{"id": case["id"], "configuration": case.get("configuration"), "server_file": case.get("file"), "passed": case["passed"],
               "connect_s": case.get("connect_s"), "transfer_s": case.get("transfer_s")} for case in chain_cases]
    checks = [{"id": case["id"], "what": case["what"], "passed": case["passed"], "seconds": case["seconds"],
               "message": clean(str(case.get("message") or case.get("reason") or ""), args.server_host)} for case in check_cases]
    evidence = {"run": {"date": args.date, "head": args.head, "device": production["device"], "android": production["android"]},
                "summary": {"chains": len(chains), "chains_passed": sum(case["passed"] for case in chains),
                            "checks": len(checks), "checks_passed": sum(case["passed"] for case in checks),
                            "skipped": [item["file"] for item in production.get("skipped", [])]},
                "chains": chains, "checks": checks}
    text = json.dumps(evidence, indent=1)
    found = PUBLIC_IPV4.findall(text)
    if found:
        sys.exit(f"Public addresses left in the evidence: {sorted(set(found))}")
    Path(args.output).write_text(text + "\n")


def render(args):
    evidence = json.loads(Path(args.evidence).read_text())
    summary = evidence["summary"]
    rows = []
    for case in sorted(evidence["chains"], key=lambda item: item["id"]):
        title = html.escape(title_of({**case, "kind": "production", "sni": case["id"].endswith("typed-sni")}))
        rows.append(f'<tr><td><a href="scenarios/{case["id"]}.html">{title}</a></td><td>{VERIFIED if case["passed"] else FAILED}</td>'
                    f'<td>{case["connect_s"]} s</td><td>{case["transfer_s"]} s</td></tr>')
    checks = [f'<tr><td>{html.escape(case["what"])}{" <em>" + html.escape(case["message"]) + "</em>" if case["message"] else ""}</td>'
              f'<td>{VERIFIED if case["passed"] else FAILED}</td></tr>' for case in evidence["checks"]]
    block = (f'<p><strong>{summary["chains_passed"]} of {summary["chains"]}</strong> chains and <strong>{summary["checks_passed"]} of {summary["checks"]}</strong> checks passed.</p>\n'
             '<h3 id="android-chains">Every chain of the production server</h3>\n'
             '<p>Each link opens the chain\'s scenario page, with its server file and the app settings, which are the same on both systems. The times show that traffic moved, and are not a benchmark.</p>\n'
             '<table><thead><tr><th>Chain</th><th>Result</th><th>To Connected</th><th>Two downloads and two uploads at once, 16 MiB each</th></tr></thead><tbody>\n'
             + "\n".join(rows) + '\n</tbody></table>\n'
             '<h3 id="android-checks">Everything around the connection</h3>\n'
             '<p>Each of these ran on the phone and on the emulator, except the always-on check, which ran on the emulator because the test drives Android\'s own settings screen. '
             'On the phone, the network check moved between its real Wi-Fi and cellular connections and the sleep checks turned its screen off.</p>\n'
             '<table><thead><tr><th>What we checked</th><th>Result</th></tr></thead><tbody>\n' + "\n".join(checks) + '\n</tbody></table>\n')
    page = SITE / "waterwall" / "android.html"
    text = page.read_text()
    updated, count = re.subn(r"(<!-- android:begin -->\n).*?(<!-- android:end -->)", lambda m: m[1] + block + m[2], text, flags=re.S)
    if count != 1:
        sys.exit("android.html has no android:begin and android:end block")
    page.write_text(updated)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    one = commands.add_parser("extract")
    for name in ("production", "lifecycle"):
        one.add_argument(f"--{name}", required=True, nargs="+")
    for name in ("server-host", "date", "head", "output"):
        one.add_argument(f"--{name}", required=True)
    two = commands.add_parser("render")
    two.add_argument("--evidence", required=True)
    args = parser.parse_args()
    extract(args) if args.command == "extract" else render(args)


if __name__ == "__main__":
    main()
