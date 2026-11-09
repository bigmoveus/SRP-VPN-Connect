module srp/wg-bridge

go 1.26.0

require (
	github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828
	golang.org/x/sys v0.47.0
	golang.zx2c4.com/wireguard v0.0.0-20261006164505-2631ce99a06f
)

require (
	github.com/google/btree v1.1.3 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
)

replace github.com/amnezia-vpn/amneziawg-go/v3 => github.com/bigmoveus/amneziawg-go/v3 v3.1.20260828-srp.1
