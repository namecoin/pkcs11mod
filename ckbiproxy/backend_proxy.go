// Copyright 2018 Namecoin Developers GPLv3+

package main

import (
	"log"

	"github.com/miekg/pkcs11"
)

type BackendProxy struct {
}

var realBackend *pkcs11.Ctx

func init() {
	realBackend = pkcs11.New("/usr/lib64/libnssckbi.so")
}

func (b BackendProxy) Initialize() error {
	log.Println("Proxy pkcs11 backend initialized")
	return realBackend.Initialize()
}

func (b BackendProxy) Finalize() error {
	log.Println("Proxy pkcs11 backend closing")
	return realBackend.Finalize()
}

func (b BackendProxy) GetInfo() (pkcs11.Info, error) {
	log.Println("Proxy pkcs11 backend GetInfo")
	return realBackend.GetInfo()
}
