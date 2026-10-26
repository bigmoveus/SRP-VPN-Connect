#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

for tool in git go rustup cargo cmake; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Required build tool not found: $tool" >&2
        exit 1
    fi
done

"$ROOT/Aether/build_aether.sh"
"$ROOT/WireGuard/build_wg.sh"
"$ROOT/WaterWall/build.sh" ios

echo "Native runtimes are ready. Run pod install and open SRP-VPN-Connect.xcworkspace."
