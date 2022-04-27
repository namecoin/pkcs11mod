// Copyright 2022 Namecoin Developers LGPLv3+
// Copyright 2021 Andreas @ryrun MIT

package pkcs11mod

import (
	"log"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"unsafe"

	//"golang.org/x/sys/windows"
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
	if trace {
		log.Println("pkcs11mod: Maybe pinning module")
	}

	// Module pinning seems incompatible with Mozilla E10S (Firefox logs
	// "Failed to launch tab subprocess"), so only enable module pinning based
	// on EXE name whitelist.
	exePath, err := os.Executable()
	if err != nil {
		log.Printf("pkcs11mod: Error detecting executable name: %s", err)
		return
	}

	exe := filepath.Base(exePath)

	shouldPinDLL := false

	switch exe {
	case "certutil.exe":
		shouldPinDLL = true
	case "firefox.exe":
		shouldPinDLL = false
	case "icecat.exe":
		shouldPinDLL = false
	case "librewolf.exe":
		shouldPinDLL = false
	default:
		log.Println("pkcs11mod: Unknown exe name '%s'.  This is probably fine, but if you see this application crash, consider reporting a bug to pkcs11mod; provide the exe name from this log message.", exe)
	}

	if !shouldPinDLL {
		if trace {
			log.Println("pkcs11mod: Not pinning module")
		}

		return
	}

	// Copied nearly verbatim from pipelined/vst2
	const (
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS = 4
		GET_MODULE_HANDLE_EX_FLAG_PIN          = 1
	)
	var (
		kernel32, _          = syscall.LoadLibrary("kernel32.dll")
		getModuleHandleEx, _ = syscall.GetProcAddress(kernel32, "GetModuleHandleExW")
		handle               uintptr
	)
	defer func(handle syscall.Handle) {
		err := syscall.FreeLibrary(handle)
		if err != nil {
			log.Println("pkcs11mod: Can't unload kernel32 lib")
		}
	}(kernel32)
	if _, _, callErr := syscall.Syscall(uintptr(getModuleHandleEx), 3, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN, reflect.ValueOf(preventUnload).Pointer(), uintptr(unsafe.Pointer(&handle))); callErr != 0 {
		log.Println("pkcs11mod: Can't pin module")
	}

	if trace {
		log.Println("pkcs11mod: Pinned module")
	}
}
