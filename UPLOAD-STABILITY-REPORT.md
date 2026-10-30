# WaterWall Upload Stability Report

## Project

- Main project root: `/Users/admin/Desktop/3in122 9/SRP-VPN-Connect`
- Scope: intermittent upload failures in the WaterWall VMess/TCP data path on a physical iPhone.
- Status: investigation and traffic testing stopped at the user's request. Migration into the main project is separate work and does not establish that the upload problem is fixed.

## Current status

The problem is **not conclusively fixed**. One complete 180-second Release test succeeded, but later runs again produced `network connection was lost` or a timeout. The current changes must not be considered a stable or release-ready resolution.

Tests used four concurrent downloads and four concurrent uploads of 16 MiB each against the test server. Server-side and device-side logs were compared where available.

## Observed failure modes

- Upload interruption with `The network connection was lost`.
- Slow uploads that timed out, including cases where the server returned HTTP 200 near the client's timeout boundary.
- A native VMess closure with `reason=retained_input`, followed by `Socket is not connected` in the application.
- A separate failure under an 8-by-8 diagnostic load; this is outside the main 4-by-4 acceptance scenario and does not share a confirmed root cause with the other failures.

## Successful 180-second Release run

| Measurement | Result |
|---|---:|
| Actual duration | 195.25 seconds |
| Downloaded | 4,630,511,616 bytes — 189.73 Mbps |
| Uploaded | 452,984,832 bytes — 18.56 Mbps |
| Transfer errors | 0 |
| Timeouts | 0 |
| VPN state at the end | Connected |
| Final ping | 1130 ms |

This proves only that this particular run passed. It does not prove that the intermittent failures have been eliminated.

## Technical evidence

- One failing Release run recorded `VmessClient ... reason=retained_input` in its native log. VMess closes the flow when input cannot be admitted to its queue, after which the application reports that the socket is no longer connected.
- The relevant admission sites are:
  - `WaterWall/upstream/tunnels/VmessClient/upstream/payload.c:48`
  - `WaterWall/upstream/tunnels/VmessClient/downstream/payload.c:18`
- The configured queue limits are defined in `WaterWall/upstream/tunnels/VmessClient/include/VmessClient/structure.h:32`: 4 MiB of data, 8 MiB of allocation charge, and 1024 entries. The evidence gathered so far does not identify which dimension was exhausted or which pause/resume transition allowed it to happen.
- The server also confirmed incomplete request bodies. In one case it received only 950,272 of the expected 16,777,216 bytes and logged `Incomplete upload`. Another failing request delivered only 819,200 bytes. These are genuine interrupted transfers, not just an overly short test timeout.
- Increasing the test request timeout from 45 to 120 seconds made the harness less likely to abort a slow but progressing request. It did not fix the underlying connection loss.
- The earlier `SRPTunnel exceeded mem limit: ActiveHard 50 MB (fatal)` kernel message was confirmed. After allocator and backpressure changes, no Jetsam was seen in the subsequently captured stress runs. That improvement alone does not make upload stable.
- More recent failing runs did not record `retained_input`. Therefore, all observed interruptions cannot yet be attributed to one root cause.

## Non-traffic checks

- iOS on the physical device: 121 tests, 2 skipped, 0 failures.
- macOS: 98 tests, 2 skipped, 0 failures.
- Host tests: 4 of 4 passed.
- Normal Release application build: succeeded.

These results cover build health and regression tests; they do not prove stable high-throughput upload.

## Changes and unfinished work

The working tree contains changes to allocator selection, independent TX/RX backpressure, the live test harness, and diagnostics. The diagnostic `liveDiagnostics` path, queue-pressure messages, and logging filters must be reviewed and cleaned before any release.

The temporary test HTTP listener on the server must also be stopped and its previous state restored when work resumes. The production service was not intentionally changed.

The final in-progress traffic test was cancelled at the user's request and has no complete result.

## Recommended continuation

1. Capture the exact `bytes`, `charge`, `entries`, and pause state at the moment a failing VMess input is rejected, and correlate the same connection with the server log.
2. Inspect the pending upstream/downstream queues and TX/RX pause-resume transitions instead of simply increasing memory or queue limits.
3. Do not treat a larger timeout or a smaller window as a complete fix.
4. Require several consecutive full 180-second Release runs with zero incomplete uploads, zero timeouts, and zero Jetsam before calling the issue fixed.
5. Review and remove temporary diagnostics, then restore the temporary server listener state before release.

## Sensitive information

Server credentials, account passwords, private keys, access tokens, and protocol UUIDs are intentionally omitted from this report.
