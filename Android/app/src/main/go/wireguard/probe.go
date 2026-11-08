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

type probeTUN struct {
	tun.Device
	file   *os.File
	inject chan []byte
	probes chan []byte
	flows  atomic.Pointer[[]probeFlow]
}

func newProbeTUN(device tun.Device) *probeTUN {
	t := &probeTUN{Device: device, inject: make(chan []byte, 64), probes: make(chan []byte, 256)}
	if native, ok := device.(interface{ File() *os.File }); ok {
		t.file = native.File()
	}
	t.flows.Store(&[]probeFlow{})
	return t
}

// Read gives the engine a submitted probe packet first; a submit cuts a waiting TUN read short with a deadline
func (t *probeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		select {
		case packet := <-t.inject:
			sizes[0] = copy(bufs[0][offset:], packet)
			return 1, nil
		default:
		}
		count, err := t.Device.Read(bufs, sizes, offset)
		if err != nil && t.file != nil && errors.Is(err, os.ErrDeadlineExceeded) {
			t.file.SetReadDeadline(time.Time{})
			continue
		}
		return count, err
	}
}

func (t *probeTUN) Write(bufs [][]byte, offset int) (int, error) {
	flows := *t.flows.Load()
	if len(flows) == 0 {
		return t.Device.Write(bufs, offset)
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
		if _, err := t.Device.Write(pass, offset); err != nil {
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

func (t *probeTUN) submit(packet []byte) {
	select {
	case t.inject <- packet:
		if t.file != nil {
			t.file.SetReadDeadline(time.Now())
		}
	default:
	}
}

func main() {}
