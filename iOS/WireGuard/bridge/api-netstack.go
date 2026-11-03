/* SPDX-License-Identifier: MIT
 * Copyright (C) 2026 SRP
 *
 * Netstack mode (golang.zx2c4.com/wireguard/tun/netstack): a WireGuard
 * device on a userspace gVisor TUN — no real utun — plus a loopback TCP
 * relay that dials a fixed target through the tunnel. Used by Aether
 * "Private" mode: hev bridges the device utun to a local SOCKS5 address,
 * the relay carries that SOCKS5 stream through WireGuard to the VPS-hosted
 * Aether proxy, so traffic exits via Cloudflare WARP rather than the VPS.
 *
 * Exports: srpwgNetstackStart / srpwgNetstackStop
 */

package main

import "C"

import (
	"io"
	"net"
	"net/netip"
	"sync"

	wgconn "golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type netstackRelay struct {
	dev    *wgdevice.Device
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
	CLogger(1).Printf("netstack: "+format, args...)
}

//export srpwgNetstackStart
func srpwgNetstackStart(cUapi *C.char, cIfAddr *C.char, cListen *C.char, cTarget *C.char) int32 {
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
	dev := wgdevice.NewDevice(tunDev, wgconn.NewStdNetBind(), &wgdevice.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	})
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
	return h
}

//export srpwgNetstackStop
func srpwgNetstackStop(handle int32) {
	nsMu.Lock()
	r := nsRelays[handle]
	delete(nsRelays, handle)
	nsMu.Unlock()
	if r == nil {
		return
	}
	r.ln.Close()
	r.dev.Close()
	nsLog("stopped (handle %d)", handle)
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
