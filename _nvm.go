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
#include "pkcs11go.h"
*/
import "C"

import (
	"io"
	"log"
	"os"

	_ "github.com/miekg/pkcs11"
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

func main(){}
