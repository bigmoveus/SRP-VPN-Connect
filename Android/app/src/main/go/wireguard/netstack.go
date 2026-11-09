//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * Netstack mode for Aether's Private mode (the iOS bridge's api-netstack.go): a WireGuard device on a userspace gVisor
 * TUN, no TUN of the system, plus a loopback TCP relay that dials one target through it. hev (libsrpaether.so) bridges
 * the VPN's TUN to a local SOCKS5 address; the relay carries that SOCKS5 stream through WireGuard to the Aether proxy on
 * the user's server, so the traffic leaves through Cloudflare WARP. WireGuard and AmneziaWG do not use this file.
 */
package main

import "C"

import (
	"io"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type netstackRelay struct {
	dev    *device.Device
	ln     net.Listener
	tnet   *netstack.Net
	target string
}

var (
	nsMu     sync.Mutex
	nsNext   int32 = 1
	nsRelays       = map[int32]*netstackRelay{}
)

func nsLog(format string, args ...interface{}) {
	logLine("E ", "netstack: "+format, args...)
}

//export srpWgNetstackStart
func srpWgNetstackStart(cUapi *C.char, cIfAddr *C.char, cListen *C.char, cTarget *C.char) C.int {
	uapi := C.GoString(cUapi)
	ifAddr := C.GoString(cIfAddr)
	listen := C.GoString(cListen)
	target := C.GoString(cTarget)

	addr, err := netip.ParseAddr(ifAddr)
	if err != nil {
		nsLog("bad interface address %q: %v", ifAddr, err)
		return -1
	}
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, 1420)
	if err != nil {
		nsLog("CreateNetTUN: %v", err)
		return -2
	}
	dev := device.NewDevice(tunDev, conn.NewStdNetBind(), &device.Logger{Verbosef: verbosef, Errorf: errorf})
	if err := dev.IpcSet(uapi); err != nil {
		nsLog("IpcSet: %v", err)
		dev.Close()
		return -3
	}
	if err := dev.Up(); err != nil {
		nsLog("device up: %v", err)
		dev.Close()
		return -4
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		nsLog("listen %q: %v", listen, err)
		dev.Close()
		return -5
	}
	r := &netstackRelay{dev: dev, ln: ln, tnet: tnet, target: target}
	go r.acceptLoop()

	nsMu.Lock()
	h := nsNext
	nsNext++
	nsRelays[h] = r
	nsMu.Unlock()
	nsLog("up: relay %s -> %s (handle %d)", listen, target, h)
	return C.int(h)
}

//export srpWgNetstackStop
func srpWgNetstackStop(handle C.int) {
	nsMu.Lock()
	r := nsRelays[int32(handle)]
	delete(nsRelays, int32(handle))
	nsMu.Unlock()
	if r == nil {
		return
	}
	r.ln.Close()
	r.dev.Close()
	nsLog("stopped (handle %d)", int32(handle))
}

func (r *netstackRelay) acceptLoop() {
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		go r.handle(c)
	}
}

type closeWriter interface {
	CloseWrite() error
}

func (r *netstackRelay) handle(c net.Conn) {
	defer c.Close()
	up, err := r.tnet.Dial("tcp", r.target)
	if err != nil {
		nsLog("dial %s through tunnel: %v", r.target, err)
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(up, c)
		if cw, ok := up.(closeWriter); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(c, up)
		if cw, ok := c.(closeWriter); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	up.Close()
}
