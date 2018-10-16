// Copyright 2018 Namecoin Developers GPLv3+

package main

import (
	"log"
)

type BackendNamecoin struct {
}

func (b BackendNamecoin) Initialize() error {
	log.Println("Namecoin pkcs11 backend initialized")
	return nil
}

func (b BackendNamecoin) Finalize() error {
	log.Println("Namecoin pkcs11 backend closing")
	return nil
}
