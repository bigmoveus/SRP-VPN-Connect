#!/usr/bin/env python3
import re
import subprocess
import sys
from pathlib import Path

source = Path(sys.argv[1])
output = Path(sys.argv[2])
symbols = set()
for name in ("libcrypto.num", "libssl.num"):
    for line in (source / "util" / name).read_text().splitlines():
        fields = line.split()
        if fields and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", fields[0]):
            symbols.add(fields[0])
if len(sys.argv) > 3:
    build = Path(sys.argv[3])
    for name in ("libcrypto.a", "libssl.a"):
        archive = build / name
        if archive.exists():
            output_text = subprocess.check_output(["nm", "-g", "--defined-only", str(archive)], text=True)
            for line in output_text.splitlines():
                fields = line.split()
                symbol = fields[-1].removeprefix("_") if fields else ""
                if symbol and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol):
                    symbols.add(symbol.removeprefix("srpww_"))
if output.exists():
    for line in output.read_text().splitlines():
        match = re.fullmatch(r"#define ([A-Za-z_][A-Za-z0-9_]*) srpww_\1", line)
        if match:
            symbols.add(match.group(1))

header_dirs = (source / "include" / "openssl",)
macro_names = set()
for directory in header_dirs:
    if not directory.is_dir():
        continue
    for header in directory.glob("*.h"):
        if header.name == "prefix_symbols.h":
            continue
        for line in header.read_text().splitlines():
            match = re.match(r"\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)", line)
            if match:
                macro_names.add(match.group(1))
symbols.difference_update(macro_names)

with output.open("w") as handle:
    handle.write("#ifndef SRP_WW_OPENSSL_PREFIX_H\n#define SRP_WW_OPENSSL_PREFIX_H\n")
    for symbol in sorted(symbols):
        handle.write(f"#ifndef {symbol}\n")
        handle.write(f"#define {symbol} srpww_{symbol}\n")
        handle.write("#endif\n")
    handle.write("#endif\n")
