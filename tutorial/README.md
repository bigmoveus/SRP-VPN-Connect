# SRP VPN Connect documentation site

A static site (HTML, CSS and JavaScript, no build step) with the WaterWall guides, and later SSTP. It can be served by GitHub Pages or copied to the app's website as it is.

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
| `sstp/` | SSTP section (phase 2) |
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

## Checking locally

```bash
cd tutorial && python3 -m http.server 8765
```

Then open <http://localhost:8765/>. Search needs a web server; it does not work from `file://`.

## Publishing on GitHub Pages

Publish the `tutorial` folder as the site root, for example with a Pages workflow that uploads `tutorial/` as the artifact. All links are relative, so the site also works from a subfolder of the app's website.
