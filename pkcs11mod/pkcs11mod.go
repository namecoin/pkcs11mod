// Copyright 2018 Namecoin Developers GPLv3+

//go:generate make clean all

package pkcs11mod

/*
#cgo windows CFLAGS: -DPACKED_STRUCTURES
#cgo windows LDFLAGS: -lpkcs11_exported -L .
#cgo linux LDFLAGS: -lpkcs11_exported -ldl -L .
#cgo darwin CFLAGS: -I/usr/local/share/libtool
#cgo darwin LDFLAGS: -lpkcs11_exported -L/usr/local/lib/ -L .
#cgo openbsd CFLAGS: -I/usr/local/include/
#cgo openbsd LDFLAGS: -lpkcs11_exported -L/usr/local/lib/ -L .
#cgo freebsd CFLAGS: -I/usr/local/include/
#cgo freebsd LDFLAGS: -lpkcs11_exported -L/usr/local/lib/ -L .
#cgo LDFLAGS: -lpkcs11_exported -L .

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "spec/pkcs11go.h"
#include "namecoin.h"
*/
import "C"

import (
	"io"
	"log"
	"os"
	"unsafe"
)

var logfile io.Closer
var backend Backend

func init() {
	f, err := os.OpenFile(os.Getenv("HOME")+"/testlogfile", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	log.SetOutput(f)
	logfile = f
	log.Println("Namecoin PKCS#11 module loading")
}

func SetBackend(b Backend) {
	backend = b
}

//export GoLog
func GoLog(s unsafe.Pointer) {
	log.Println(C.GoString((*C.char)(s)))
}

//export Go_Initialize
func Go_Initialize() C.CK_RV {
	err := backend.Initialize()
	return fromError(err)
}

//export Go_Finalize
func Go_Finalize() C.CK_RV {
	err := backend.Finalize()
	return fromError(err)
}

//export Go_GetInfo
func Go_GetInfo(p C.CK_INFO_PTR) C.CK_RV {
	// TODO: Packing on Windows may break in this function.  Should we be
	// using C.ckInfo here?

	if (p == nil) {
		return C.CKR_ARGUMENTS_BAD;
	}

	info, err := backend.GetInfo()
	if err != nil {
		return fromError(err)
	}

	p.cryptokiVersion.major = C.CK_BYTE(info.CryptokiVersion.Major)
	p.cryptokiVersion.minor = C.CK_BYTE(info.CryptokiVersion.Minor)
	p.flags = C.CK_FLAGS(info.Flags)
	p.libraryVersion.major = C.CK_BYTE(info.LibraryVersion.Major)
	p.libraryVersion.minor = C.CK_BYTE(info.LibraryVersion.Minor)

	// CK_INFO strings have a max length of 32, as per Sec. 3.1 of the
	// PKCS#11 spec.
	if len(info.ManufacturerID) > 32 {
		info.ManufacturerID = info.ManufacturerID[:32]
	}
	if len(info.LibraryDescription) > 32 {
		info.LibraryDescription = info.LibraryDescription[:32]
	}

	// CK_INFO strings must be padded with the space character and not
	// null-terminated, as per Sec. 3.1 of the PKCS#11 spec.
	for x := 0; x < 32; x++ {
		p.manufacturerID[x] = C.CK_UTF8CHAR(' ')
		p.libraryDescription[x] = C.CK_UTF8CHAR(' ')
	}

	// Copy the ManufacturerID
	for i, ch := range info.ManufacturerID {
		p.manufacturerID[i] = C.CK_UTF8CHAR(ch)
	}
	// Copy the LibraryDescription
	for i, ch := range info.LibraryDescription {
		p.libraryDescription[i] = C.CK_UTF8CHAR(ch)
	}

	return fromError(err)
}

//export Go_GetSlotList
func Go_GetSlotList(tokenPresent C.CK_BBOOL, pSlotList C.CK_SLOT_ID_PTR, pulCount C.CK_ULONG_PTR) C.CK_RV {
	if (pulCount == nil) {
		return C.CKR_ARGUMENTS_BAD;
	}

	goTokenPresent := fromCBBool(tokenPresent)

	slotList, err := backend.GetSlotList(goTokenPresent)
	if err != nil {
		return fromError(err)
	}

	goCount := uint(len(slotList))

	if pSlotList == nil {
		// Only return the number of slots
		*pulCount = C.CK_ULONG(goCount)
	} else {
		// Return number of slots and list of slots

		// Check to make sure that the buffer is big enough
		goRequestedCount := uint(*pulCount)
		if goRequestedCount < goCount {
			return C.CKR_BUFFER_TOO_SMALL
		}

		*pulCount = C.CK_ULONG(goCount)
		fromList(slotList, C.CK_ULONG_PTR(pSlotList), goCount)
	}

	return fromError(err)
}

// The exported functions below this point are totally unused and are probably totally broken.

//export Go_GetTokenInfo
func Go_GetTokenInfo(slotID uint) C.CK_RV {
	log.Println("GetTokenInfo")
	return C.CKR_OK
}

//export Go_OpenSession
func Go_OpenSession(slotID uint, flags uint) C.CK_RV {
	log.Println("OpenSession")
	return C.CKR_OK
}

//export Go_GetMechanismList
func Go_GetMechanismList(slotID uint) C.CK_RV {
	log.Println("GetMechanismList")
	return C.CKR_OK
}
