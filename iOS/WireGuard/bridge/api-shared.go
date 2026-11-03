/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2026 SRP — merged dual-engine variant (wireguard-go + amneziawg-go).
 *
 * Shared plumbing for the SRP WireGuard/AmneziaWG bridge: one Go runtime
 * drives both engines, because two c-archives in one process would clash
 * (each ships its own runtime; mixing them corrupts the heap).
 */

package main

// #include <stdlib.h>
// #include <sys/types.h>
// static void callLogger(void *func, void *ctx, int level, const char *msg)
// {
// 	((void(*)(void *, int, const char *))func)(ctx, level, msg);
// }
import "C"

import (
	"fmt"
	"math"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

var loggerFunc unsafe.Pointer
var loggerCtx unsafe.Pointer

type CLogger int

func cstring(s string) *C.char {
	b, err := unix.BytePtrFromString(s)
	if err != nil {
		b := [1]C.char{}
		return &b[0]
	}
	return (*C.char)(unsafe.Pointer(b))
}

func (l CLogger) Printf(format string, args ...interface{}) {
	if uintptr(loggerFunc) == 0 {
		return
	}
	C.callLogger(loggerFunc, loggerCtx, C.int(l), cstring(fmt.Sprintf(format, args...)))
}

func init() {
	signals := make(chan os.Signal)
	signal.Notify(signals, unix.SIGUSR2)
	go func() {
		buf := make([]byte, os.Getpagesize())
		for {
			select {
			case <-signals:
				n := runtime.Stack(buf, true)
				buf[n] = 0
				if uintptr(loggerFunc) != 0 {
					C.callLogger(loggerFunc, loggerCtx, 0, (*C.char)(unsafe.Pointer(&buf[0])))
				}
			}
		}
	}()
}

// engineDevice is satisfied by both golang.zx2c4.com/wireguard/device.Device
// and github.com/amnezia-vpn/amneziawg-go/v3/device.Device.
type engineDevice interface {
	IpcSet(string) error
	IpcGet() (string, error)
	Up() error
	Close()
	BindUpdate() error
	SendKeepalivesToPeersWithCurrentKeypair()
	DisableSomeRoamingForBrokenMobileSemantics()
}

// engineLogger wraps the Errorf field of either engine's device.Logger.
type engineLogger struct {
	errorf func(format string, args ...interface{})
}

func (l engineLogger) Errorf(format string, args ...interface{}) {
	l.errorf(format, args...)
}

// CLoggerPair mirrors the Logger struct shape of both engines.
type CLoggerPair struct {
	Verbosef func(format string, args ...interface{})
	Errorf   func(format string, args ...interface{})
}

func (l CLoggerPair) logErrorf(format string, args ...interface{}) {
	l.Errorf(format, args...)
}

type tunnelHandle struct {
	device engineDevice
	logger engineLogger
}

var tunnelHandles = make(map[int32]tunnelHandle)

// registerTunnel returns a free handle or -1.
func registerTunnel(h tunnelHandle) int32 {
	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		return -1
	}
	tunnelHandles[i] = h
	return i
}

// turnOnDevice attaches an engine to the extension's utun fd: duplicates and
// non-blocks the fd, builds the device via makeDevice, applies the UAPI
// settings and brings the device up.
func turnOnDevice(settings string, tunFd int32,
	makeDevice func(unixFd int, log CLoggerPair) (engineDevice, engineLogger, error)) int32 {
	logger := CLoggerPair{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}
	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		logger.logErrorf("Unable to dup tun fd: %v", err)
		return -1
	}
	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		logger.logErrorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	dev, engLogger, err := makeDevice(dupTunFd, logger)
	if err != nil {
		logger.logErrorf("Unable to create device: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	err = dev.IpcSet(settings)
	if err != nil {
		logger.logErrorf("Unable to set IPC settings: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	err = dev.Up()
	if err != nil {
		logger.logErrorf("Unable to bring the device up: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	logger.Verbosef("Device started")
	return registerTunnel(tunnelHandle{dev, engLogger})
}

// setLoggerShared implements both wgSetLogger and awgSetLogger.
func setLoggerShared(context, loggerFn uintptr) {
	loggerCtx = unsafe.Pointer(context)
	loggerFunc = unsafe.Pointer(loggerFn)
}

// turnOffShared implements both wgTurnOff and awgTurnOff.
func turnOffShared(handle int32) {
	h, ok := tunnelHandles[handle]
	if !ok {
		return
	}
	delete(tunnelHandles, handle)
	h.device.Close()
}

// setConfigShared implements both wgSetConfig and awgSetConfig.
func setConfigShared(handle int32, settings string) int64 {
	h, ok := tunnelHandles[handle]
	if !ok {
		return 0
	}
	err := h.device.IpcSet(settings)
	if err != nil {
		h.logger.Errorf("Unable to set IPC settings: %v", err)
		return -1
	}
	return 0
}

// getConfigShared implements both wgGetConfig and awgGetConfig.
func getConfigShared(handle int32) *C.char {
	h, ok := tunnelHandles[handle]
	if !ok {
		return nil
	}
	settings, err := h.device.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

// bumpSocketsShared implements both wgBumpSockets and awgBumpSockets.
func bumpSocketsShared(handle int32) {
	h, ok := tunnelHandles[handle]
	if !ok {
		return
	}
	go func() {
		for i := 0; i < 10; i++ {
			err := h.device.BindUpdate()
			if err == nil {
				h.device.SendKeepalivesToPeersWithCurrentKeypair()
				return
			}
			h.logger.Errorf("Unable to update bind, try %d: %v", i+1, err)
			time.Sleep(time.Second / 2)
		}
		h.logger.Errorf("Gave up trying to update bind; tunnel is likely dysfunctional")
	}()
}

// disableRoamingShared implements both wg* and awg* variants.
func disableRoamingShared(handle int32) {
	h, ok := tunnelHandles[handle]
	if !ok {
		return
	}
	h.device.DisableSomeRoamingForBrokenMobileSemantics()
}

// versionShared reports the version of the module whose path ends with suffix.
func versionShared(suffix string) *C.char {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return C.CString("unknown")
	}
	for _, dep := range info.Deps {
		if strings.HasSuffix(dep.Path, suffix) {
			parts := strings.Split(dep.Version, "-")
			if len(parts) == 3 && len(parts[2]) == 12 {
				return C.CString(parts[2][:7])
			}
			return C.CString(dep.Version)
		}
	}
	return C.CString("unknown")
}

func main() {}
