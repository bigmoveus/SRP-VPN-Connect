package main

import "testing"

// A probe answer: TCP from 1.1.1.1:80 to the tunnel address, local port 40001
func TestIsProbe(t *testing.T) {
	packet := make([]byte, 40)
	packet[0] = 0x45
	packet[9] = 6
	copy(packet[12:16], []byte{1, 1, 1, 1})
	copy(packet[16:20], []byte{10, 66, 66, 3})
	packet[20], packet[21] = 0, 80
	packet[22], packet[23] = 0x9c, 0x41 // 40001
	flows := []probeFlow{{protocol: 6, address: [4]byte{1, 1, 1, 1}, port: 40001}}
	if !isProbe(packet, flows) {
		t.Fatal("the probe flow's answer was not recognized")
	}
	packet[23] = 0x42
	if isProbe(packet, flows) {
		t.Fatal("another local port matched")
	}
	packet[23] = 0x41
	packet[9] = 17
	if isProbe(packet, flows) {
		t.Fatal("another protocol matched")
	}
	if isProbe(packet[:20], flows) || isProbe([]byte{0x60, 0, 0, 0}, flows) {
		t.Fatal("a short or IPv6 packet matched")
	}
}
