#!/usr/bin/env python3
"""Fails when WaterWall's lwIP would share symbol names with the lwIP SSTP links.

Usage: lwip_prefix_contract.py <srp_lwip_prefix.h> <ww_lwip archive> <runtime archive>
"""
import re
import subprocess
import sys
from pathlib import Path

header, lwip_archive, runtime_archive = sys.argv[1:4]
text = Path(header).read_text()
renamed = set(re.findall(r"^#define ([A-Za-z_][A-Za-z0-9_]*) srpww_\1$", text, re.M))
kept_line = re.search(r"^// kept:(.*)$", text, re.M)
kept = set(kept_line.group(1).split()) if kept_line else set()


def symbols(archive, *flags):
    output = subprocess.check_output(["nm", "-g", *flags, archive], text=True)
    names = set()
    for line in output.splitlines():
        fields = line.split()
        if fields and not line.endswith(":"):
            names.add(fields[-1].removeprefix("_"))
    return names


# WaterWall's engine glue keeps its own ww* namespace, which no other lwIP uses.
unprefixed = sorted(name for name in symbols(lwip_archive, "--defined-only")
                    if not name.startswith(("srpww_", "ww")) and name not in kept)
defined = sorted(renamed & symbols(runtime_archive, "--defined-only"))
referenced = sorted(renamed & symbols(runtime_archive, "-u"))
if not renamed or unprefixed or defined or referenced:
    raise SystemExit("lwIP prefix contract failed: "
                     f"not in {Path(header).name}={unprefixed[:20]}, "
                     f"defined unprefixed={defined[:20]}, referenced unprefixed={referenced[:20]}")
print(f"lwIP prefix contract passed: {len(renamed)} renamed, {len(kept)} kept")
