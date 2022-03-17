// Copyright 2022 Namecoin Developers LGPLv3+

package pkcs11mod

import (
	"log"

	"golang.org/x/sys/windows"
)

// This hack prevents a segfault if the application tries to unload pkcs11mod.
// See the following references:
// https://github.com/golang/go/issues/11100#issuecomment-489066651
// https://blogs.msmvps.com/vandooren/2006/10/09/preventing-a-dll-from-being-unloaded-by-the-app-that-uses-it/
// https://stackoverflow.com/a/14436845
// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexa?redirectedfrom=MSDN#parameters
func preventUnload() {
	// TODO: don't hardcode this module name

	moduleNameGo := "nssckbi"

	moduleNameWin, err := windows.UTF16PtrFromString(moduleNameGo)
	if err != nil {
		log.Printf("pkcs11mod: Error converting module name: %s", err)
		return
	}

	var module windows.Handle
	err = windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_PIN, moduleNameWin, &module)
	if err != nil {
		log.Printf("pkcs11mod: Error pinning module: %s", err)
		return
	}

	if trace {
		log.Println("pkcs11mod: Pinned module")
	}
}
