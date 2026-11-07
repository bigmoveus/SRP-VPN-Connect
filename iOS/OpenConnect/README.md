# OpenConnect (SSL VPN) protocol core

Native OpenConnect client for the app's SSL VPN profiles (AnyConnect, F5 BIG-IP and Palo Alto GlobalProtect), built from
the vendored **openconnect 9.21** sources (`upstream/`, LGPL-2.1 — see `upstream/COPYING.LGPL`) for both apps.

## iOS

- `build_openconnect.sh` — configures + builds `build/<platform>/libSRPOpenConnect.a`
  for `iphoneos` + `macosx` (arm64). TLS backend: the prefixed OpenSSL 3.0.15
  from `../SoftEther/openssl/` (symbols `srpse_*`, no BoringSSL clash). XML: the SDK's libxml2.
  Notes: `ac_cv_func_HMAC_CTX_copy=yes` works around autoconf's AC_CHECK_FUNC
  being incompatible with symbol prefixing; the `serverhash` tool failure at
  the end of `make` is expected (we archive the library objects ourselves).
- The extension-side adapter is `Core/SRPCore/SRPOpenConnectClient.*`; `SRPTunnel/PacketTunnelProvider.m` starts it.
- `OCTest/` — macOS E2E harness (`build.sh` + run `./octest [user] [pass] [url]`): auth, CSTP, DTLS, IP settings,
  ping and DNS through the tunnel, and negative cases (bad hostname cert reject, wrong password).

## Android

- `build_libxml2_android.sh` — downloads libxml2 2.15.4 from download.gnome.org, checks it against the published SHA-256,
  and builds `libxml2/android-arm64/{include,lib}` (static, arm64, API 26, no iconv).
- `build_openconnect_android.sh` — builds `build/android-arm64/libSRPOpenConnect.a` from the same sources with upstream's
  JNI binding (`jni.c`, `--with-java --enable-jni-standalone`), the OpenSSL 3.5 of the Android SoftEther core
  (`../SoftEther/build_openssl_android.sh`) and that libxml2. `Android/app/src/main/cpp/CMakeLists.txt` links the archive
  whole into `libsrpopenconnect.so`, beside `openconnect_tun_jni.c` (the packet channel to the tunnel and the ping's probe
  flows). The app uses upstream's `upstream/java/src/org/infradead/libopenconnect/LibOpenConnect.java` through a Gradle source
  directory; `Android/app/src/main/java/tr/com/srp/vpn/SslVpnClient.kt` mirrors the iOS adapter.

## SRP changes to the upstream sources

- TLS write splitting of the ClientHello: `openconnect_set_tls_fragmentation()` (`openconnect.h`, `library.c`,
  `openconnect-internal.h`) and the filter BIO in `openssl.c`, which is `Core/SRPCore/SRPFragBio.c`, staged into the build.
- `jni.c` and `LibOpenConnect.java`: `setTLSFragmentation(first, following, gapMs)` for the Android app.

## Tests and documentation

Server: ocserv on Ubuntu 24.04, as `tutorial/sslvpn/server.html` sets it up; the results of both apps are in
`tutorial/sslvpn/results.html`. AnyConnect is tested against ocserv; F5 BIG-IP and GlobalProtect use the same core but
were not tested against real servers.
