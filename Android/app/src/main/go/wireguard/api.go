//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * WireGuard for the Android app: wireguard-go (the version the iOS app's bridge uses) on the VpnService's TUN file
 * descriptor, driven from Kotlin through jni_android.c. The app is not routed through its own VPN, so the engine's UDP
 * sockets need no protect(). Log lines wait in a queue that Kotlin reads (srpWgNextLog). For the same reason the app
 * measures its Ping with probe packets: probeTUN hands the engine the packets the app submits as if they came from the
 * TUN, and gives the app the answers of its probe flows instead of the TUN (probe.go).
 */
package main

// #include <stdlib.h>
import "C"

import (
	"encoding/binary"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type tunnel struct {
	device *device.Device
	tun    *probeTUN
}

var (
	handles   = make(map[int32]*tunnel)
	handlesMu sync.Mutex
	logs      = make(chan string, 1024)
	verbose   atomic.Bool
)

func logLine(level string, format string, args ...interface{}) {
	select {
	case logs <- level + fmt.Sprintf(format, args...):
	default: // the reader fell behind: drop rather than block the engine
	}
}

func newLogger() *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...interface{}) {
			if verbose.Load() {
				logLine("V ", format, args...)
			}
		},
		Errorf: func(format string, args ...interface{}) { logLine("E ", format, args...) },
	}
}

//export srpWgTurnOn
func srpWgTurnOn(settings *C.char, tunFd C.int) C.int {
	logger := newLogger()
	// The service keeps its descriptor (and closes it when the tunnel goes); the engine owns and closes a duplicate
	fd, err := unix.Dup(int(tunFd))
	if err != nil {
		logger.Errorf("Unable to duplicate the TUN descriptor: %v", err)
		return -1
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		logger.Errorf("Unable to set the TUN descriptor non-blocking: %v", err)
		unix.Close(fd)
		return -1
	}
	tunDevice, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		logger.Errorf("Unable to attach to the TUN descriptor: %v", err)
		unix.Close(fd)
		return -1
	}
	probe := newProbeTUN(tunDevice)
	dev := device.NewDevice(probe, conn.NewStdNetBind(), logger)
	if err := dev.IpcSet(C.GoString(settings)); err != nil {
		logger.Errorf("Unable to set the configuration: %v", err)
		dev.Close()
		return -1
	}
	if err := dev.Up(); err != nil {
		logger.Errorf("Unable to bring the device up: %v", err)
		dev.Close()
		return -1
	}
	handlesMu.Lock()
	defer handlesMu.Unlock()
	var handle int32
	for handle = 0; handle < math.MaxInt32; handle++ {
		if _, used := handles[handle]; !used {
			break
		}
	}
	handles[handle] = &tunnel{dev, probe}
	logger.Verbosef("Device started")
	return C.int(handle)
}

func deviceOf(handle C.int) *device.Device {
	handlesMu.Lock()
	defer handlesMu.Unlock()
	if t := handles[int32(handle)]; t != nil {
		return t.device
	}
	return nil
}

func probeOf(handle C.int) *probeTUN {
	handlesMu.Lock()
	defer handlesMu.Unlock()
	if t := handles[int32(handle)]; t != nil {
		return t.tun
	}
	return nil
}

//export srpWgTurnOff
func srpWgTurnOff(handle C.int) {
	handlesMu.Lock()
	t := handles[int32(handle)]
	delete(handles, int32(handle))
	handlesMu.Unlock()
	if t != nil {
		t.device.Close()
	}
}

//export srpWgSetConfig
func srpWgSetConfig(handle C.int, settings *C.char) C.longlong {
	dev := deviceOf(handle)
	if dev == nil {
		return -1
	}
	if err := dev.IpcSet(C.GoString(settings)); err != nil {
		logLine("E ", "Unable to set the configuration: %v", err)
		return -1
	}
	return 0
}

// srpWgGetConfig returns the UAPI get text (with the private key: the caller parses it and never logs it), or NULL.
// The caller frees it.
//
//export srpWgGetConfig
func srpWgGetConfig(handle C.int) *C.char {
	dev := deviceOf(handle)
	if dev == nil {
		return nil
	}
	settings, err := dev.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

//export srpWgBumpSockets
func srpWgBumpSockets(handle C.int) {
	dev := deviceOf(handle)
	if dev == nil {
		return
	}
	// New sockets on the network the phone uses now, as the official apps do on a network change
	go func() {
		for i := 0; i < 10; i++ {
			if err := dev.BindUpdate(); err == nil {
				dev.SendKeepalivesToPeersWithCurrentKeypair()
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		logLine("E ", "Unable to update the sockets")
	}()
}

// srpWgSetProbeFlows sets the probe flows: count triples of protocol, IPv4 address (big-endian) and local port
//
//export srpWgSetProbeFlows
func srpWgSetProbeFlows(handle C.int, values *C.int, count C.int) {
	t := probeOf(handle)
	if t == nil {
		return
	}
	numbers := unsafe.Slice((*int32)(unsafe.Pointer(values)), int(count)*3)
	flows := make([]probeFlow, 0, int(count))
	for i := 0; i+2 < len(numbers); i += 3 {
		var flow probeFlow
		flow.protocol = byte(numbers[i])
		binary.BigEndian.PutUint32(flow.address[:], uint32(numbers[i+1]))
		flow.port = uint16(numbers[i+2])
		flows = append(flows, flow)
	}
	t.flows.Store(&flows)
}

//export srpWgSubmit
func srpWgSubmit(handle C.int, packet *C.char, length C.int) {
	if t := probeOf(handle); t != nil {
		t.submit(C.GoBytes(unsafe.Pointer(packet), length))
	}
}

// srpWgNextProbe waits up to timeoutMs for a probe flow's packet; it copies it into out (capacity bytes) and returns
// its length, or 0
//
//export srpWgNextProbe
func srpWgNextProbe(handle C.int, out *C.char, capacity C.int, timeoutMs C.int) C.int {
	t := probeOf(handle)
	if t == nil {
		return 0
	}
	select {
	case packet := <-t.probes:
		return C.int(copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), int(capacity)), packet))
	case <-time.After(time.Duration(timeoutMs) * time.Millisecond):
		return 0
	}
}

//export srpWgSetVerbose
func srpWgSetVerbose(on C.int) {
	verbose.Store(on != 0)
}

// srpWgNextLog waits up to timeoutMs for a log line ("E " or "V " and the text) and returns it, or NULL. The caller
// frees it.
//
//export srpWgNextLog
func srpWgNextLog(timeoutMs C.int) *C.char {
	select {
	case line := <-logs:
		return C.CString(line)
	case <-time.After(time.Duration(timeoutMs) * time.Millisecond):
		return nil
	}
}

//export srpWgFree
func srpWgFree(p *C.char) {
	C.free(unsafe.Pointer(p))
}
