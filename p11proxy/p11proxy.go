package main

import (
	"os"

	"github.com/miekg/pkcs11/p11"
	"github.com/namecoin/pkcs11mod/p11mod"
)

func init() {
	backendPath := os.Getenv("P11PROXY_CKBI_TARGET")
	if backendPath == "" {
		backendPath = "/usr/lib64/nss/libnssckbi.so"
	}

	backend, err := p11.OpenModule(backendPath)

	p11mod.SetBackend(backend, err)
}

func main() {}
