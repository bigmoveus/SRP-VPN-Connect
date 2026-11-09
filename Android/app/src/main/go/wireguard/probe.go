/* SPDX-License-Identifier: MIT
 *
 * probeTUN: the Ping of the Android app's WireGuard (see api.go), on any platform so it can be tested anywhere.
 */
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// A probe flow: packets of this protocol from this address to this local port go to the app, not to the TUN
type probeFlow struct {
	protocol byte
	address  [4]byte
	port     uint16
}

// probeCore is the probe state of a TUN, the same for both engines' TUN interfaces (probeTUN, awgProbeTUN)
type probeCore struct {
	file   *os.File
	inject chan []byte
	probes chan []byte
	flows  atomic.Pointer[[]probeFlow]
}

func newProbeCore(file *os.File) *probeCore {
	c := &probeCore{file: file, inject: make(chan []byte, 64), probes: make(chan []byte, 256)}
	c.flows.Store(&[]probeFlow{})
	return c
}

// probeTUN is wireguard-go's TUN with the probe
type probeTUN struct {
	tun.Device
	*probeCore
}

func newProbeTUN(device tun.Device) *probeTUN {
	var file *os.File
	if native, ok := device.(interface{ File() *os.File }); ok {
		file = native.File()
	}
	return &probeTUN{Device: device, probeCore: newProbeCore(file)}
}

func (t *probeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return t.read(t.Device.Read, bufs, sizes, offset)
}

func (t *probeTUN) Write(bufs [][]byte, offset int) (int, error) {
	return t.write(t.Device.Write, bufs, offset)
}

// read gives the engine a submitted probe packet first; a submit cuts a waiting TUN read short with a deadline
func (t *probeCore) read(read func([][]byte, []int, int) (int, error), bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		select {
		case packet := <-t.inject:
			sizes[0] = copy(bufs[0][offset:], packet)
			return 1, nil
		default:
		}
		count, err := read(bufs, sizes, offset)
		if err != nil && t.file != nil && errors.Is(err, os.ErrDeadlineExceeded) {
			t.file.SetReadDeadline(time.Time{})
			continue
		}
		return count, err
	}
}

func (t *probeCore) write(write func([][]byte, int) (int, error), bufs [][]byte, offset int) (int, error) {
	flows := *t.flows.Load()
	if len(flows) == 0 {
		return write(bufs, offset)
	}
	pass := make([][]byte, 0, len(bufs))
	for _, buf := range bufs {
		if packet := buf[offset:]; isProbe(packet, flows) {
			select {
			case t.probes <- append([]byte(nil), packet...):
			default:
			}
			continue
		}
		pass = append(pass, buf)
	}
	if len(pass) > 0 {
		if _, err := write(pass, offset); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}

func isProbe(packet []byte, flows []probeFlow) bool {
	if len(packet) < 24 || packet[0]>>4 != 4 {
		return false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+4 {
		return false
	}
	for _, flow := range flows {
		if packet[9] == flow.protocol && bytes.Equal(packet[12:16], flow.address[:]) &&
			binary.BigEndian.Uint16(packet[ihl+2:ihl+4]) == flow.port {
			return true
		}
	}
	return false
}

func (t *probeCore) submit(packet []byte) {
	select {
	case t.inject <- packet:
		if t.file != nil {
			t.file.SetReadDeadline(time.Now())
		}
	default:
	}
}

func main() {}
