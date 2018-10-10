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
#cgo windows LDFLAGS: -lltdl
#cgo linux LDFLAGS: -lltdl -ldl
#cgo darwin CFLAGS: -I/usr/local/share/libtool
#cgo darwin LDFLAGS: -lltdl -L/usr/local/lib/
#cgo openbsd CFLAGS: -I/usr/local/include/
#cgo openbsd LDFLAGS: -lltdl -L/usr/local/lib/
#cgo freebsd CFLAGS: -I/usr/local/include/
#cgo freebsd LDFLAGS: -lltdl -L/usr/local/lib/
#cgo LDFLAGS: -lltdl

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ltdl.h>
#include <unistd.h>
#include "namecoin.h"
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

//export C_Initialize
func C_Initialize() error {
	log.Println("Initialized!!!")
	return nil
}

//export C_GetInfo
func C_GetInfo() (string, error) {
	log.Println("Get Info")
	return "hello", nil
}

//export C_GetSlotList
func C_GetSlotList(tokenPresent bool) ([]uint, error) {
	log.Println("GetSlotList")
	return nil, nil
}

//export C_GetTokenInfo
func C_GetTokenInfo(slotID uint) (string, error) {
	log.Println("GetTokenInfo")
	return "ok", nil
}

//export C_OpenSession
func C_OpenSession(slotID uint, flags uint) (uint, error) {
	log.Println("OpenSession")
	return 42, nil
}

//export C_GetMechanismList
func C_GetMechanismList(slotID uint) ([]string, error) {
	log.Println("GetMechanismList")
	return nil, nil
}

//export C_GetFunctionList
func C_GetFunctionList(thing uintptr) ([]string, error) {
	log.Println("GetFunctionList") // actually broken
	return nil, nil
}
func main() {}
