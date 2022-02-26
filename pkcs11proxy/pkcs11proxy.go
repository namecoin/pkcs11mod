package main

import (
	"os"

	"github.com/miekg/pkcs11"
	"github.com/namecoin/pkcs11mod"
)

func init() {
	backendPath := os.Getenv("PKCS11PROXY_CKBI_TARGET")
	if backendPath == "" {
		backendPath = "/usr/lib64/nss/libnssckbi.so"
	}

	backend := pkcs11.New(backendPath)
	if backend == nil {
		return
	}

	pkcs11mod.SetBackend(backend)
}

func main() {}
