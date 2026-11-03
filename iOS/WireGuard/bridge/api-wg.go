/* SPDX-License-Identifier: MIT
 * Copyright (C) 2018-2019 Jason A. Donenfeld. All Rights Reserved.
 * Copyright (C) 2026 SRP — merged dual-engine variant.
 *
 * WireGuard (golang.zx2c4.com/wireguard) exports: wg* symbols.
 */

package main

import "C"

import (
	"os"

	wgconn "golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

//export wgSetLogger
func wgSetLogger(context, loggerFn uintptr) {
	setLoggerShared(context, loggerFn)
}

//export wgTurnOn
func wgTurnOn(settings *C.char, tunFd int32) int32 {
	return turnOnDevice(C.GoString(settings), tunFd, func(fd int, log CLoggerPair) (engineDevice, engineLogger, error) {
		l := &wgdevice.Logger{Verbosef: log.Verbosef, Errorf: log.Errorf}
		t, err := wgtun.CreateTUNFromFile(os.NewFile(uintptr(fd), "/dev/tun"), 0)
		if err != nil {
			return nil, engineLogger{}, err
		}
		l.Verbosef("Attaching to interface")
		return wgdevice.NewDevice(t, wgconn.NewStdNetBind(), l), engineLogger{errorf: l.Errorf}, nil
	})
}

//export wgTurnOff
func wgTurnOff(handle int32) {
	turnOffShared(handle)
}

//export wgSetConfig
func wgSetConfig(handle int32, settings *C.char) int64 {
	return setConfigShared(handle, C.GoString(settings))
}

//export wgGetConfig
func wgGetConfig(handle int32) *C.char {
	return getConfigShared(handle)
}

//export wgBumpSockets
func wgBumpSockets(handle int32) {
	bumpSocketsShared(handle)
}

//export wgDisableSomeRoamingForBrokenMobileSemantics
func wgDisableSomeRoamingForBrokenMobileSemantics(handle int32) {
	disableRoamingShared(handle)
}

//export wgVersion
func wgVersion() *C.char {
	return versionShared("golang.zx2c4.com/wireguard")
}
