# Third-Party Notices

SRP VPN Connect contains and builds upon independent protocol implementations and libraries. The original copyright and license notices remain part of those components. A protocol name in the profile editor does not imply endorsement by its upstream project.

## Main components

| Component | Upstream | License or notice |
| --- | --- | --- |
| SoftEther VPN | [SoftEtherVPN/SoftEtherVPN](https://github.com/SoftEtherVPN/SoftEtherVPN) | Apache License 2.0; see `SoftEther/LICENSE` |
| OpenConnect | [OpenConnect](https://www.infradead.org/openconnect/) | LGPL 2.1; see `OpenConnect/upstream/COPYING.LGPL` |
| OpenVPN 3 | [OpenVPN/openvpn3](https://github.com/OpenVPN/openvpn3) | AGPL 3.0 or MPL 2.0, with the linking permission described in `OpenVPN/upstream/LICENSE.md` |
| WireGuard / wireguard-go | [WireGuard](https://www.wireguard.com/) | MIT; see `Licenses/WireGuard/LICENSE` |
| AmneziaWG-go | [amnezia-vpn/amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) | MIT; see `Licenses/AmneziaWG/LICENSE` |
| Aether | [CluvexStudio/Aether](https://github.com/CluvexStudio/Aether) | AGPL 3.0; see `Licenses/Aether/LICENSE` and `Licenses/Aether/TRADEMARK.md` |
| Psiphon clientlib | [Psiphon-Labs/psiphon-tunnel-core](https://github.com/Psiphon-Labs/psiphon-tunnel-core) | GPL 3.0; see `Licenses/Psiphon/LICENSE` |
| WaterWall | [radkesvat/WaterWall](https://github.com/radkesvat/WaterWall) | See `WaterWall/upstream/LICENSE.txt` and the notices in its source directories |
| BoringSSL | [BoringSSL](https://boringssl.googlesource.com/boringssl/) | See `Licenses/BoringSSL/LICENSE` |
| OpenSSL | [OpenSSL](https://www.openssl.org/) | Apache License 2.0; see `Licenses/OpenSSL/LICENSE.txt` |
| lwIP | [lwIP](https://savannah.nongnu.org/projects/lwip/) | See the notices in the lwIP source tree |
| hev-socks5-tunnel and related components | [Heiher](https://github.com/heiher) | See `SSH/upstream/LICENSE` and the related component notices |
| libssh2 | [libssh2](https://libssh2.org/) | See `SSH/libssh2/COPYING` |
| IQKeyboardManager | [hackiftekhar/IQKeyboardManager](https://github.com/hackiftekhar/IQKeyboardManager) | MIT; see `Licenses/IQKeyboardManager/LICENSE.md` |
| Toast | [scalessec/Toast](https://github.com/scalessec/Toast) | MIT; see `Licenses/Toast/LICENSE` |

JSONCPP, LZ4, Asio, BoringSSL, OpenSSL, and other bundled dependencies retain their notices in their source directories. The OpenVPN build also uses the license files supplied by those components.

## Downloaded dependencies

The build scripts retrieve pinned public sources for Aether and Psiphon. Go and Rust dependencies are resolved through their module manifests. WaterWall's CMake build can also retrieve its declared public dependencies. Their licenses accompany the corresponding downloaded source trees.

Where an upstream project offers a choice of licenses, this notice does not narrow that choice. Review the upstream terms before redistributing a compiled application or a modified component.
