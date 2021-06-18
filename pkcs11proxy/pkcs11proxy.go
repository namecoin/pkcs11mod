package main

import (
	"github.com/miekg/pkcs11"
	"github.com/namecoin/pkcs11mod"
)

func init() {
	backend := pkcs11.New("/usr/lib64/nss/libnssckbi.so")

	pkcs11mod.SetBackend(backend)
}

func main() {}
