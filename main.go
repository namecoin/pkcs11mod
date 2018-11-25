// Copyright 2018 Namecoin Developers LGPLv3+

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

import (
	"github.com/namecoin/nctls.so/pkcs11mod"
)

func init() {
	backend := BackendNamecoin{}

	pkcs11mod.SetBackend(backend)
}

func main() {}
