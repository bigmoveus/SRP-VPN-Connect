# SRP VPN Connect documentation site

A static site (HTML, CSS and JavaScript, no build step) with the WaterWall, SSTP and SoftEther VPN guides. It can be served by GitHub Pages or copied to the app's website as it is.

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

## Checking locally

```bash
cd tutorial && python3 -m http.server 8765
```

Then open <http://localhost:8765/>. Search needs a web server; it does not work from `file://`.

## Publishing on GitHub Pages

Publish the `tutorial` folder as the site root, for example with a Pages workflow that uploads `tutorial/` as the artifact. All links are relative, so the site also works from a subfolder of the app's website.
