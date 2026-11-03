/* SPDX-License-Identifier: MIT
 * Copyright (C) 2026 SRP
 *
 * Psiphon clientlib (psiphon-tunnel-core) wrapped into this bridge so the
 * app has ONE Go runtime — a second c-archive in the process would clash
 * with the wireguard-go runtime.
 *
 * Exports: srppsiStart / srppsiStop
 *   srppsiStart(configJSON, embeddedServerEntryList, dataRoot) -> JSON
 *   C string: {"ok":true,"socks":<port>} or {"ok":false,"error":"..."}
 */

package main

import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/ClientLibrary/clientlib"
)

var (
	psiMu     sync.Mutex
	psiTunnel *clientlib.PsiphonTunnel
	psiCancel context.CancelFunc
)

//export srppsiStart
func srppsiStart(cConfig *C.char, cEntries *C.char, cDataRoot *C.char) *C.char {
	psiMu.Lock()
	defer psiMu.Unlock()

	configJSON := []byte(C.GoString(cConfig))
	entries := C.GoString(cEntries)
	dataRoot := C.GoString(cDataRoot)

	params := clientlib.Parameters{
		DataRootDirectory: &dataRoot,
	}
	platform := "iOS_tr.com.srp.vpn"
	params.ClientPlatform = &platform
	networkID := "WIFI"
	params.NetworkID = &networkID
	timeout := 60
	params.EstablishTunnelTimeoutSeconds = &timeout

	// Forward tunnel-core notices (chosen transport, errors) to the log
	noticeLog := func(ev clientlib.NoticeEvent) {
		CLogger(1).Printf("[psi] %s %v", ev.Type, ev.Data)
	}

	ctx, cancel := context.WithCancel(context.Background())
	tunnel, err := clientlib.StartTunnel(ctx, configJSON, entries, params, nil, noticeLog)
	if err != nil {
		cancel()
		return C.CString(fmt.Sprintf(`{"ok":false,"error":%q}`, err.Error()))
	}
	psiTunnel = tunnel
	psiCancel = cancel
	return C.CString(fmt.Sprintf(`{"ok":true,"socks":%d,"http":%d,"connect_ms":0}`,
		tunnel.SOCKSProxyPort, tunnel.HTTPProxyPort))
}

//export srppsiStop
func srppsiStop() {
	psiMu.Lock()
	defer psiMu.Unlock()
	if psiTunnel != nil {
		psiTunnel.Stop()
		psiTunnel = nil
	}
	if psiCancel != nil {
		psiCancel()
		psiCancel = nil
	}
}

// keep the imports honest if the compiler disagrees about usage
var _ = json.Marshal
var _ = time.Now
