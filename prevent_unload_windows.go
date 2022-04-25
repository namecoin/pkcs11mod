// Copyright 2022 Namecoin Developers LGPLv3+

package pkcs11mod

import (
	"log"
	"reflect"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This hack prevents a segfault if the application tries to unload pkcs11mod.
// See the following references:
// https://github.com/golang/go/issues/11100#issuecomment-489066651
// https://github.com/golang/go/issues/11100#issuecomment-932638093
// https://blogs.msmvps.com/vandooren/2006/10/09/preventing-a-dll-from-being-unloaded-by-the-app-that-uses-it/
// https://stackoverflow.com/a/14436845
// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexa?redirectedfrom=MSDN#parameters
// https://github.com/pipelined/vst2/blob/bc659a1443b585c376cc25a6d13614488c9fa4ee/plugin_export_windows.go#L11-L34
func preventUnload() {
	// See https://pkg.go.dev/unsafe#Pointer (reflect.Value.Pointer)
	moduleAddressWin := (*uint16)(unsafe.Pointer(reflect.ValueOf(preventUnload).Pointer()))

	var module windows.Handle
	err := windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|windows.GET_MODULE_HANDLE_EX_FLAG_PIN, moduleAddressWin, &module)
	if err != nil {
		log.Printf("pkcs11mod: Error pinning module: %s", err)
		return
	}

	if trace {
		log.Println("pkcs11mod: Pinned module")
	}
}