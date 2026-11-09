# SRP VPN Connect documentation site

A static site (HTML, CSS and JavaScript, no build step) with the WaterWall, SSTP, SoftEther VPN, SSL VPN, SSH VPN, OpenVPN, WireGuard, AmneziaWG and Aether guides. It can be served by GitHub Pages or copied to the app's website as it is.

## Rules for content

- English only.
- Only what we tested ourselves, on the current app build and the current server versions. Older results are not used.
- Pages describe the current state: what to do, how it is set up, what a message means, what was tested. They do not say what went wrong and got fixed, and they keep no failure history.
- Each scenario carries one status: VERIFIED — TESTED SUCCESSFULLY, TESTED — FAILED, TESTED — PARTIALLY WORKING, NOT VERIFIED, or PLANNED — NOT TESTED.
- Secrets and our infrastructure are replaced with placeholders such as `<SERVER_HOST>`, `<SERVER_IP>`, `<UUID>` and `<PASSWORD>`.
- `EVIDENCE-INVENTORY.md` records where each claim comes from. It is for us and is not linked from the pages.

## Layout

| Path | Content |
|---|---|
| `index.html`, `future.html` | Home and the future-protocols page |
| `waterwall/` | WaterWall guides |
| `waterwall/scenarios/` | One page per tested scenario, generated |
| `waterwall/android.html` | What differs on Android, and the Android results, generated into its `android:begin` block |
| `sstp/` | SSTP section (phase 2) |
| `softether/` | SoftEther VPN section: server, app setup, results, troubleshooting |
| `sslvpn/` | SSL VPN section: ocserv server, app setup, configuration reference, results, troubleshooting |
| `ssh/` | SSH VPN section: OpenSSH server and UDP relay, app setup, configuration reference, results, troubleshooting |
| `openvpn/` | OpenVPN section: OpenVPN 2.6 server with stunnel, app setup, configuration reference, results, troubleshooting |
| `wireguard/` | WireGuard section: WireGuard server on Ubuntu 24.04, app setup, configuration reference, results, troubleshooting |
| `amneziawg/` | AmneziaWG section: AmneziaWG server on Ubuntu 24.04 with our amneziawg-go fork and the awg tools from the Amnezia packages, app setup, configuration reference, results, troubleshooting |
| `aether/` | Aether section: Public mode (Cloudflare WARP with no server) and Private mode (a server on Ubuntu 24.04 with WireGuard and our Aether engine in Docker), app setup, configuration reference, results, troubleshooting |
| `assets/css/site.css` | All styles, light and dark |
| `assets/js/nav.js` | The navigation tree |
| `assets/js/site.js` | Header, sidebar, table of contents, search, theme and copy buttons |
| `assets/img/` | Screenshots |
| `evidence/` | Sanitized results of each test run, used to generate the scenario pages |
| `tools/` | The scenario page generator and its shared text |

## Adding a page

1. Copy an existing page in the same folder and keep its `<head>` and the two script tags at the end.
2. Put the content inside `<main>`. The sidebar, table of contents and search are added by `site.js`.
3. Add the page to `assets/js/nav.js`. Search only covers pages listed there.

## Scenario pages

The scenario pages come from a test run of `WaterWall/tests/device_matrix.py`:

```bash
python3 tutorial/tools/waterwall_scenarios.py extract --work <harness work folder> --provenance <provenance.txt> \
  --selection <matrix-selection.json> --server-ip <server IP> --server-host <server name> --client-ip <office IP> \
  --device-id <device UDID> \
  --environment '{"profile": "device-matrix"}' --output tutorial/evidence/<run name>.json
```

```bash
python3 tutorial/tools/waterwall_scenarios.py render --environment tutorial/tools/scenario-environments.json \
  --intro tutorial/tools/scenarios-intro.html --evidence tutorial/evidence/*.json
```

`extract` refuses to write a file that still contains a public IPv4 address or a path on the Mac that ran the tests. `render` rewrites `waterwall/scenarios/` and the block between `scenarios:begin` and `scenarios:end` in `nav.js`.

A case that runs again goes into a new evidence file named after the run's start time in UTC, such as `waterwall-matrix-20261103T0623Z.json`. Remove that case from the older file, so each page shows only the latest result, and count only the cases that stay in that file's `summary`. A case run in several rounds keeps the first round's details and lists the others under `later_rounds`. A run under different conditions gets its own profile in `scenario-environments.json`, which names a `base` profile and only what differs.

The screenshots come from the unit test `testDocumentationScreenshotsWhenRequested`, run on the test iPhone with `TEST_RUNNER_SRP_DOCS_SCREENSHOTS=1`. It writes PNG files to `tmp/srp-docs-screenshots` in the app's data container.

## Android results and screenshots

The Android runs come from the private test tools, `run_production.py` and `run_lifecycle.py`, on the test phone and the Android emulator:

```bash
python3 tutorial/tools/android_results.py extract --production <results.json files> --lifecycle <results.json files> \
  --server-host <server name> --date <YYYY-MM-DD> --head <commit> --output tutorial/evidence/android-waterwall-<date>.json
python3 tutorial/tools/android_results.py render --evidence tutorial/evidence/android-waterwall-<date>.json
```

`extract` refuses to write a file that still contains a public IPv4 address, and of a case run more than once it keeps the last file's run. The Android screenshots in `assets/img/waterwall/android/` come from `docs_screenshots.py` in the same tools, with the same example profiles as the iPhone ones.

## SoftEther results and screenshots

The SoftEther runs come from the private test tools in `softether/`: `run_profile_cases.py` on the iPhone and `run_android.py` and `run_android_lifecycle.py` on the Android phone, over the cases of `cases-full.json`:

```bash
python3 tutorial/tools/softether_results.py extract --cases <cases-full.json> --ios <results.json files> \
  --android <results.json files> --replace <server name>=<SERVER_HOST> <server IP>=<SERVER_IP> <proxy IP>=<PROXY_HOST> \
  --egress <server IP> --date "<day month year>" --iphone "<phone>" --android-device "<phone>" --app "<build>" \
  --server "<server>" --output tutorial/evidence/softether-<date>.json
python3 tutorial/tools/softether_results.py render --evidence tutorial/evidence/softether-<date>.json
```

`extract` refuses to write a file that still contains a public IPv4 address or a path on the Mac. `render` rewrites `softether/results.html` from `tools/softether-results-intro.html`. The iPhone screenshots in `assets/img/softether/` come from the unit test `testSoftEtherDocumentationScreenshotsWhenRequested` with `TEST_RUNNER_SRP_DOCS_SCREENSHOTS=1`, which writes them to `tmp/srp-docs-screenshots-softether` in the app's data container; the Android ones in `assets/img/softether/android/` come from `docs_screenshots_android.py` on the emulator.

## SSL VPN results and screenshots

The SSL VPN runs come from the private test tools in `openconnect/`: `run_profile_cases.py` on the iPhone and `run_android.py` and `run_android_lifecycle.py` on the Android phone, over the cases of `cases-full.json` (`make_oc_cases.py`):

```bash
python3 tutorial/tools/sslvpn_results.py extract --cases <cases-full.json> <cases-path.json> --ios <results.json files> \
  --android <results.json files> --replace <server name>=<SERVER_HOST> <server IP>=<SERVER_IP> \
  --egress <server IP> --date "<day month year>" --iphone "<phone>" --android-device "<phone>" --app "<build>" \
  --server "<server>" --output tutorial/evidence/sslvpn-<date>.json
python3 tutorial/tools/sslvpn_results.py render --evidence tutorial/evidence/sslvpn-<date>.json
```

`extract` works as for SoftEther; `render` rewrites `sslvpn/results.html` from `tools/sslvpn-results-intro.html`. The iPhone screenshots in `assets/img/sslvpn/` come from the unit test `testSslVpnDocumentationScreenshotsWhenRequested` (written to `tmp/srp-docs-screenshots-sslvpn`), the Android ones in `assets/img/sslvpn/android/` from `docs_screenshots_android.py` on the emulator.

## SSH VPN results and screenshots

The SSH VPN runs come from the private test tools in `ssh/`: `run_profile_cases.py` on the iPhone and `run_android.py` and `run_android_lifecycle.py` on the Android phone, over the cases of `cases-full.json` (`make_ssh_cases.py`):

```bash
python3 tutorial/tools/ssh_results.py extract --cases <cases-full.json> --ios <results.json files> \
  --android <results.json files> --replace <server IP>=<SERVER_IP> <office IP>=<OFFICE_IP> \
  <server's ED25519 fingerprint>=SHA256:<SERVER_ED25519_KEY> \
  --egress <server IP> --date "<day month year>" --iphone "<phone>" --android-device "<phone>" --app "<build>" \
  --server "<server>" --output tutorial/evidence/ssh-<date>.json
python3 tutorial/tools/ssh_results.py render --evidence tutorial/evidence/ssh-<date>.json
```

`extract` refuses to write a file that still contains a public IPv4 address, a path on the Mac or a host key fingerprint, so the server's fingerprint, which the host key cases' messages name, must be replaced too. `render` rewrites `ssh/results.html` from `tools/ssh-results-intro.html`. The iPhone screenshots in `assets/img/ssh/` come from the unit test `testSshDocumentationScreenshotsWhenRequested` (written to `tmp/srp-docs-screenshots-ssh`), the Android ones in `assets/img/ssh/android/` from `docs_screenshots_android.py` on the emulator.

## OpenVPN results and screenshots

The OpenVPN runs come from the private test tools in `openvpn/`: `run_profile_cases.py` on the iPhone and `run_android.py` and `run_android_lifecycle.py` on the Android phone, over the cases of `cases-full.json` (`make_ovpn_cases.py`):

```bash
python3 tutorial/tools/openvpn_results.py extract --cases <cases-full.json> <cases-release.json> <cases-guide.json> --ios <results.json files> \
  --android <results.json files> --replace <server IP>=<SERVER_IP> <office IP>=<OFFICE_IP> <server name>=<SERVER_HOST> \
  --egress <server IP> --date "<day month year>" --iphone "<phone>" --android-device "<phone>" --app "<build>" \
  --server "<server>" --output tutorial/evidence/openvpn-<date>.json
python3 tutorial/tools/openvpn_results.py render --evidence tutorial/evidence/openvpn-<date>.json
```

`extract` refuses to write a file that still contains a public IPv4 address or a path on the Mac. `render` rewrites `openvpn/results.html` from `tools/openvpn-results-intro.html`. The iPhone screenshots in `assets/img/openvpn/` come from the unit test `testOpenVpnDocumentationScreenshotsWhenRequested` (written to `tmp/srp-docs-screenshots-openvpn`), the Android ones in `assets/img/openvpn/android/` from `docs_screenshots_android.py` on the emulator.

## WireGuard results and screenshots

The WireGuard runs come from the private test tools in `wireguard/`: `run_profile_cases.py` on the iPhone and `run_android.py` and `run_android_lifecycle.py` on the Android phone, over the cases of `cases-full.json` (`make_wg_cases.py`):

```bash
python3 tutorial/tools/wireguard_results.py extract --cases <cases-full.json> <cases-release.json> <cases-guide.json> \
  --android-cases <Android case lists> --ios <results.json files> --android <results.json files> \
  --replace <server IP>=<SERVER_IP> <office IP>=<OFFICE_IP> <server name>=<SERVER_HOST> --server-ip <server IP> \
  --date "<day month year>" --iphone "<phone>" --android-device "<phone>" --app "<build>" --server "<server>" \
  --output tutorial/evidence/wireguard-<date>.json
python3 tutorial/tools/wireguard_results.py render --evidence tutorial/evidence/wireguard-<date>.json
```

`extract` refuses to write a file that still contains a public IPv4 address or a path on the Mac; `--server-ip` is only compared with the answers of the UDP cases and is never written. `render` rewrites `wireguard/results.html` from `tools/wireguard-results-intro.html`. The iPhone screenshots in `assets/img/wireguard/` come from the unit test `testWireGuardDocumentationScreenshotsWhenRequested` (written to `tmp/srp-docs-screenshots-wireguard`), the Android ones in `assets/img/wireguard/android/` from `docs_screenshots_android.py` on the emulator.

## AmneziaWG results and screenshots

The AmneziaWG runs come from the private test tools in `amneziawg/`: `run_profile_cases.py` on the iPhone and `run_android.py` and `run_android_lifecycle.py` on the Android phone, over the cases of `cases-full.json` (`make_awg_cases.py`) and the RandomTrailers cases of `cases-fork.json`, against the eight test interfaces of `server-setup.sh` and `fork-tests-setup.sh` on our amneziawg-go fork (`fork-server-switch.sh` moved the server from the kernel module, whose four `awg-kernel-module-…` rows were run before it); `lab-evidence.sh` runs amneziawg-go as Amnezia releases it as a client on the server itself:

```bash
python3 tutorial/tools/amneziawg_results.py extract --cases <cases-full.json> <cases-release.json> <cases-guide.json> \
  --android-cases <Android case lists> --ios <results.json files> --android <results.json files> \
  --replace <server IP>=<SERVER_IP> <client IP>=<CLIENT_IP> <server name>=<SERVER_HOST> --server-ip <server IP> \
  --date "<day month year>" --iphone "<phone>" --android-device "<phone>" --app "<build>" --server "<server>" \
  --output tutorial/evidence/amneziawg-<date>.json
python3 tutorial/tools/amneziawg_results.py render --evidence tutorial/evidence/amneziawg-<date>.json
```

`extract` refuses to write a file that still contains a public IPv4 address or a path on the Mac; `--server-ip` is only compared with the answers of the UDP cases and is never written. `render` rewrites `amneziawg/results.html` from `tools/amneziawg-results-intro.html`. The iPhone screenshots in `assets/img/amneziawg/` come from the unit test `testAmneziaWGDocumentationScreenshotsWhenRequested` (written to `tmp/srp-docs-screenshots-amneziawg`), the Android ones in `assets/img/amneziawg/android/` from `docs_screenshots_android.py` on the emulator.

## Aether results and screenshots

The Aether runs come from the private test tools in `aether/`: `run_profile_cases.py` (through `run-ios.zsh`) on the iPhone and `run_android.py` and `run_android_lifecycle.py` on the Android phone, over the cases of `cases-full.json`, `cases-life.json` and `cases-guide.json`; Public mode connects to Cloudflare WARP, Private mode to the test server, and `guide_run.py` runs the steps of `aether/server.html` on it as the page shows them:

```bash
python3 tutorial/tools/aether_results.py extract --cases <cases-full.json> <cases-life.json> <cases-guide.json> \
  --ios <results.json files> --android <results.json files> \
  --replace <server IP>=<SERVER_IP> <client IP>=<CLIENT_IP> <server name>=<SERVER_HOST> \
  --date "<day month year>" --iphone "<phone>" --android-device "<phone>" --app "<build>" --server "<server>" \
  --output tutorial/evidence/aether-<date>.json
python3 tutorial/tools/aether_results.py render --evidence tutorial/evidence/aether-<date>.json
```

`extract` refuses to write a file that still contains a public IPv4 address or a path on the Mac; the addresses the test server saw are only looked up for their network (AS number) and never written. `render` rewrites `aether/results.html` from `tools/aether-results-intro.html`. The iPhone screenshots in `assets/img/aether/` come from the unit test `testAetherDocumentationScreenshotsWhenRequested` (written to `tmp/srp-docs-screenshots-aether`), the Android ones in `assets/img/aether/android/` from `docs_screenshots_android.py` on the emulator.

## Checking locally

```bash
cd tutorial && python3 -m http.server 8765
```

Then open <http://localhost:8765/>. Search needs a web server; it does not work from `file://`.

## Publishing on GitHub Pages

Publish the `tutorial` folder as the site root, for example with a Pages workflow that uploads `tutorial/` as the artifact. All links are relative, so the site also works from a subfolder of the app's website.
