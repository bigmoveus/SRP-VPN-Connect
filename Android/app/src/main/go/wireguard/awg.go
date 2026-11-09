//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * AmneziaWG for the Android app: amneziawg-go (the version of the iOS app's bridge) beside wireguard-go in the same library,
 * so one Go runtime serves both. Everything after the start (settings, state, sockets, the Ping probe) goes through the engine
 * interface in api.go.
 */
package main

// #include <stdlib.h>
import "C"

import (
	"golang.org/x/sys/unix"

	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	awgdevice "github.com/amnezia-vpn/amneziawg-go/v3/device"
	awgtun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

var _ engine = (*awgdevice.Device)(nil)

// awgProbeTUN is probeTUN for amneziawg-go's TUN interface (its Events() type is its own)
type awgProbeTUN struct {
	awgtun.Device
	*probeCore
}

func (t *awgProbeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return t.read(t.Device.Read, bufs, sizes, offset)
}

func (t *awgProbeTUN) Write(bufs [][]byte, offset int) (int, error) {
	return t.write(t.Device.Write, bufs, offset)
}

//export srpAwgTurnOn
func srpAwgTurnOn(settings *C.char, tunFd C.int) C.int {
	logger := &awgdevice.Logger{Verbosef: verbosef, Errorf: errorf}
	fd, ok := dupTUN(int(tunFd))
	if !ok {
		return -1
	}
	tunDevice, _, err := awgtun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		fail("Unable to attach to the TUN descriptor: %v", err)
		unix.Close(fd)
		return -1
	}
	probe := &awgProbeTUN{Device: tunDevice, probeCore: newProbeCore(tunDevice.File())}
	dev := awgdevice.NewDevice(probe, awgconn.NewStdNetBind(), logger)
	return start(dev, probe.probeCore, C.GoString(settings))
}
