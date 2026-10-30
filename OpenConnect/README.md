# OpenConnect (AnyConnect) protocol core

Native OpenConnect client for the SRPTunnel network extension, built from the
vendored **openconnect 9.21** sources (`upstream/`, LGPL-2.1 — see
`upstream/COPYING.LGPL`).

- `build_openconnect.sh` — configures + builds `build/<platform>/libSRPOpenConnect.a`
  for `iphoneos` + `macosx` (arm64). TLS backend: the prefixed OpenSSL 3.0.15
  from `../SoftEther/openssl/` (symbols `srpse_*`, no BoringSSL clash).
  Notes: `ac_cv_func_HMAC_CTX_copy=yes` works around autoconf's AC_CHECK_FUNC
  being incompatible with symbol prefixing; the `serverhash` tool failure at
  the end of `make` is expected (we archive the library objects ourselves).
- `OCTest/` — macOS E2E harness (`build.sh` + run `./octest [user] [pass] [url]`).
  Verifies auth, CSTP, DTLS, IP settings, ping and DNS through the tunnel, plus
  negative cases (bad hostname cert reject, wrong password).
- Server: ocserv on `openconnect.srp.services:443` (users sstp-test1/2,
  plain auth, SecureNAT-style NAT, range 10.82.0.0/24).

The extension-side Objective-C adapter is `Core/SRPCore/SRPOpenConnectClient.*`.
v1 scope: AnyConnect protocol, password auth, SecTrust validation, DTLS,
IPv4+IPv6 settings, auto-reconnect, switch-to-Wi-Fi. Client-cert auth and
proxy are wired in the adapter but not enabled in the UI yet.
