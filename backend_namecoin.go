// Copyright 2018 Namecoin Developers LGPLv3+

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

func (b BackendNamecoin) GetSlotList(tokenPresent bool) ([]uint, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b BackendNamecoin) GetSlotInfo(slotID uint) (pkcs11.SlotInfo, error) {
	return pkcs11.SlotInfo{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b BackendNamecoin) GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error) {
	return pkcs11.TokenInfo{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b BackendNamecoin) OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error) {
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b BackendNamecoin) Login(sh pkcs11.SessionHandle, userType uint, pin string) error {
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b BackendNamecoin) GetObjectSize(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) (uint, error) {
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b BackendNamecoin) GetAttributeValue(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b BackendNamecoin) FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error {
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b BackendNamecoin) FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	return nil, false, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}
