#!/bin/sh
set -eu

case "${1:-}" in
    host|ios) preset="$1" ;;
    *) echo "usage: $0 host|ios" >&2; exit 64 ;;
esac

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$root"
expected=c5a0d7727e279cd957d421c56a1aba33c45ab2c5
if [ -d "$root/upstream/.git" ]; then
    actual=$(git -C "$root/upstream" rev-parse HEAD)
    if [ "$actual" != "$expected" ]; then
        echo "WaterWall upstream must remain at $expected (found $actual)" >&2
        exit 65
    fi
fi

cmake --preset "$preset" -S "$root"
cmake --build --preset "$preset" --target SRPWaterWallRuntime -j8
if [ "$preset" = host ]; then
    cmake --build --preset host --target srp_waterwall_host_poc srp_waterwall_expanded_chain_poc srp_waterwall_vless_mux_udp_poc -j8
    ctest --preset host --output-on-failure
fi
