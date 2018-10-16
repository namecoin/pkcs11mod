// Copyright 2018 Namecoin Developers GPLv3+

// Build with this makefile:
/*
NAME ?= 'libnamecoin.so'
.PHONY: ${NAME}
${NAME}:
	CGO_ENABLED=1 go build -buildmode c-shared -o ${NAME}
clean:
    rm libnamecoin.h libnamecoin.so
*/

package main

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
	"unsafe"
	"log"
	"os"
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

	backend = BackendNamecoin{}
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
	log.Println("Go_Finalize")
	return C.CKR_OK
}

//export Go_GetInfo
func Go_GetInfo(p C.CK_INFO_PTR) C.CK_RV {
	if (p == nil) {
		return C.CKR_ARGUMENTS_BAD;
	}
	log.Println("GetInfo")
	p.cryptokiVersion.major = C.uchar(0x02);
	p.cryptokiVersion.minor = C.uchar(0x14);
	p.flags = 0
	p.libraryVersion.major = C.NCTLS_Version_Major
	p.libraryVersion.minor = C.NCTLS_Version_Minor
	for x := 0; x < 32; x++ {
		p.manufacturerID[x] = ' '
		p.libraryDescription[x] = ' '
	}
	for i, ch := range C.NCTLS_ManufacturerID {
		p.manufacturerID[i] = C.uchar(ch)
	}
	return C.CKR_OK
}

// The exported functions below this point are totally unused and are probably totally broken.

//export Go_GetSlotList
func Go_GetSlotList(tokenPresent bool) C.CK_RV {
	log.Println("GetSlotList")
	return C.CKR_OK
}

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

func main() {}
