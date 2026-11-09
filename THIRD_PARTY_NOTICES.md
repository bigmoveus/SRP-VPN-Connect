# Third-Party Notices

SRP VPN Connect contains and builds upon independent protocol implementations and libraries. The original copyright and license notices remain part of those components. A protocol name in the profile editor does not imply endorsement by its upstream project.

## Main components

| Component | Upstream | License or notice |
| --- | --- | --- |
| SoftEther VPN (client core of the iOS and Android apps) | [SoftEtherVPN/SoftEtherVPN](https://github.com/SoftEtherVPN/SoftEtherVPN) | Apache License 2.0; see `iOS/SoftEther/LICENSE` |
| OpenConnect (SSL VPN core of the iOS and Android apps) | [OpenConnect](https://www.infradead.org/openconnect/) | LGPL 2.1; see `iOS/OpenConnect/upstream/COPYING.LGPL` |
| libxml2 (in the Android SSL VPN core) | [GNOME/libxml2](https://gitlab.gnome.org/GNOME/libxml2) | MIT; see `Licenses/libxml2/Copyright` |
| OpenVPN 3 | [OpenVPN/openvpn3](https://github.com/OpenVPN/openvpn3) | AGPL 3.0 or MPL 2.0, with the linking permission described in `iOS/OpenVPN/upstream/LICENSE.md` |
| WireGuard / wireguard-go | [WireGuard](https://www.wireguard.com/) | MIT; see `Licenses/WireGuard/LICENSE` |
| AmneziaWG-go (the iOS and Android apps build our fork [bigmoveus/amneziawg-go](https://github.com/bigmoveus/amneziawg-go), tag `v3.1.20260828-srp.1`: upstream v3.1.20260828 with a fix for transport packets taken for handshake messages with RandomTrailers) | [amnezia-vpn/amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) | MIT; see `Licenses/AmneziaWG/LICENSE` |
| Aether | [CluvexStudio/Aether](https://github.com/CluvexStudio/Aether) | AGPL 3.0; see `Licenses/Aether/LICENSE` and `Licenses/Aether/TRADEMARK.md` |
| Psiphon clientlib | [Psiphon-Labs/psiphon-tunnel-core](https://github.com/Psiphon-Labs/psiphon-tunnel-core) | GPL 3.0; see `Licenses/Psiphon/LICENSE` |
| WaterWall | [radkesvat/WaterWall](https://github.com/radkesvat/WaterWall) | See `WaterWall/upstream/LICENSE.txt` and the notices in its source directories |
| BoringSSL | [BoringSSL](https://boringssl.googlesource.com/boringssl/) | See `Licenses/BoringSSL/LICENSE` |
| OpenSSL (3.0 in the iOS SoftEther core, 3.5 in the Android one, 4.0 in the WaterWall runtime) | [OpenSSL](https://www.openssl.org/) | Apache License 2.0; see `Licenses/OpenSSL/LICENSE.txt` |
| lwIP | [lwIP](https://savannah.nongnu.org/projects/lwip/) | See the notices in the lwIP source tree |
| sstp-client (SSTP code of the iOS and Android apps) | sstp-client by Eivind Naess | GPL 2.0 or later; see the notices in `iOS/Core/SRPCore/sstp` |
| hev-socks5-tunnel and related components | [Heiher](https://github.com/heiher) | See `iOS/SSH/upstream/LICENSE` and the related component notices |
| libssh2 | [libssh2](https://libssh2.org/) | See `iOS/SSH/libssh2/COPYING` |
| IQKeyboardManager | [hackiftekhar/IQKeyboardManager](https://github.com/hackiftekhar/IQKeyboardManager) | MIT; see `Licenses/IQKeyboardManager/LICENSE.md` |
| Toast | [scalessec/Toast](https://github.com/scalessec/Toast) | MIT; see `Licenses/Toast/LICENSE` |
| libmaxminddb | [maxmind/libmaxminddb](https://github.com/maxmind/libmaxminddb) | Apache License 2.0; see the notice in the vendored dependency |
| GeoLite2 Country data | [MaxMind GeoLite2](https://www.maxmind.com/en/geolite2/signup) | This product includes GeoLite2 data created by MaxMind, available from [maxmind.com](https://www.maxmind.com), under the [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/). |

JSONCPP, LZ4, Asio, BoringSSL, OpenSSL, and other bundled dependencies retain their notices in their source directories. The OpenVPN build also uses the license files supplied by those components.

## Downloaded dependencies

The build scripts retrieve pinned public sources for Aether and Psiphon. Go and Rust dependencies are resolved through their module manifests. WaterWall's CMake build can also retrieve its declared public dependencies. Their licenses accompany the corresponding downloaded source trees.

Where an upstream project offers a choice of licenses, this notice does not narrow that choice. Review the upstream terms before redistributing a compiled application or a modified component.
