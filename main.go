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
#cgo windows LDFLAGS: -lltdl -lpkcs11_exported -L .
#cgo linux LDFLAGS: -lltdl -lpkcs11_exported -ldl -L .
#cgo darwin CFLAGS: -I/usr/local/share/libtool
#cgo darwin LDFLAGS: -lltdl -lpkcs11_exported -L/usr/local/lib/ -L .
#cgo openbsd CFLAGS: -I/usr/local/include/
#cgo openbsd LDFLAGS: -lltdl -lpkcs11_exported -L/usr/local/lib/ -L .
#cgo freebsd CFLAGS: -I/usr/local/include/
#cgo freebsd LDFLAGS: -lltdl -lpkcs11_exported -L/usr/local/lib/ -L .
#cgo LDFLAGS: -lltdl -lpkcs11_exported -L .

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ltdl.h>
#include <unistd.h>
#include "namecoin.h"
#include "pkcs11go.h"
*/
import "C"

import (
	"io"
	"log"
	"os"
)

var logfile io.Closer

func init() {
	f, err := os.OpenFile(os.Getenv("HOME")+"/testlogfile", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	log.SetOutput(f)
	logfile = f
	log.Println("Namecoin PKCS#11 module loading")
}

//export Go_Initialize
func Go_Initialize() C.CK_RV {
	log.Println("Initialized!!!")
	return C.CKR_OK
}

// The exported functions below this point are totally unused and are probably totally broken.

//export Go_GetInfo
func Go_GetInfo() (string, error) {
	log.Println("Get Info")
	return "hello", nil
}

//export Go_GetSlotList
func Go_GetSlotList(tokenPresent bool) ([]uint, error) {
	log.Println("GetSlotList")
	return nil, nil
}

//export Go_GetTokenInfo
func Go_GetTokenInfo(slotID uint) (string, error) {
	log.Println("GetTokenInfo")
	return "ok", nil
}

//export Go_OpenSession
func Go_OpenSession(slotID uint, flags uint) (uint, error) {
	log.Println("OpenSession")
	return 42, nil
}

//export Go_GetMechanismList
func Go_GetMechanismList(slotID uint) ([]string, error) {
	log.Println("GetMechanismList")
	return nil, nil
}

func main() {}
