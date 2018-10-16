// Copyright 2018 Namecoin Developers GPLv3+

package main

import (
	"log"

	"github.com/miekg/pkcs11"
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

func (b BackendNamecoin) GetInfo() (pkcs11.Info, error) {
	log.Println("Namecoin pkcs11 backend GetInfo")
	info := pkcs11.Info{
		CryptokiVersion:    pkcs11.Version{2, 20},
		ManufacturerID:     "Namecoin TLS",
		Flags:              0,
		LibraryDescription: "Testing 1 2 3",
		LibraryVersion:     pkcs11.Version{0, 0},
	}
	return info, nil
}
