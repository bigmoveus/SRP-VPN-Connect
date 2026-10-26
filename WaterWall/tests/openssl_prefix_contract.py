#!/usr/bin/env python3
import subprocess
import sys

symbols = set()
for archive in sys.argv[1:]:
    output = subprocess.check_output(["nm", "-g", "--defined-only", archive], text=True)
    for line in output.splitlines():
        fields = line.split()
        if fields:
            symbols.add(fields[-1].lstrip("_"))
required = {
    "srpww_CRYPTO_realloc",
    "srpww_CRYPTO_memcmp",
    "srpww_OPENSSL_sk_push",
    "srpww_OPENSSL_sk_new_reserve",
    "srpww_ossl_property_string_data_new",
    "srpww_EVP_DigestSqueeze",
}
forbidden = {
    "CRYPTO_realloc",
    "CRYPTO_memcmp",
    "OPENSSL_sk_push",
    "OPENSSL_sk_new_reserve",
    "ossl_property_string_data_new",
    "EVP_DigestSqueeze",
}
missing = sorted(required - symbols)
colliding = sorted(forbidden & symbols)
if missing or colliding:
    raise SystemExit(f"OpenSSL prefix contract failed: missing={missing}, unprefixed={colliding}")
print(f"OpenSSL prefix contract passed for {len(sys.argv) - 1} archives")
