/* SPDX-License-Identifier: MIT
 * Copyright (C) 2018-2019 Jason A. Donenfeld. All Rights Reserved.
 * Copyright (C) 2026 SRP — merged dual-engine variant.
 *
 * AmneziaWG (github.com/amnezia-vpn/amneziawg-go/v3) exports: awg* symbols.
 */

package main

import "C"

import (
	"os"

	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	awgdevice "github.com/amnezia-vpn/amneziawg-go/v3/device"
	awgtun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

//export awgSetLogger
func awgSetLogger(context, loggerFn uintptr) {
	setLoggerShared(context, loggerFn)
}

//export awgTurnOn
func awgTurnOn(settings *C.char, tunFd int32) int32 {
	return turnOnDevice(C.GoString(settings), tunFd, func(fd int, log CLoggerPair) (engineDevice, engineLogger, error) {
		l := &awgdevice.Logger{Verbosef: log.Verbosef, Errorf: log.Errorf}
		t, err := awgtun.CreateTUNFromFile(os.NewFile(uintptr(fd), "/dev/tun"), 0)
		if err != nil {
			return nil, engineLogger{}, err
		}
		l.Verbosef("Attaching to interface")
		return awgdevice.NewDevice(t, awgconn.NewStdNetBind(), l), engineLogger{errorf: l.Errorf}, nil
	})
}

//export awgTurnOff
func awgTurnOff(handle int32) {
	turnOffShared(handle)
}

//export awgSetConfig
func awgSetConfig(handle int32, settings *C.char) int64 {
	return setConfigShared(handle, C.GoString(settings))
}

//export awgGetConfig
func awgGetConfig(handle int32) *C.char {
	return getConfigShared(handle)
}

//export awgBumpSockets
func awgBumpSockets(handle int32) {
	bumpSocketsShared(handle)
}

//export awgDisableSomeRoamingForBrokenMobileSemantics
func awgDisableSomeRoamingForBrokenMobileSemantics(handle int32) {
	disableRoamingShared(handle)
}

//export awgVersion
func awgVersion() *C.char {
	return versionShared("amneziawg-go")
}
