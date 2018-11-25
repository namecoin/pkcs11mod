// Copyright 2018 Namecoin Developers LGPLv3+

package pkcs11mod

import (
	"github.com/miekg/pkcs11"
)

// Backend is an interface compatible with pkcs11.Ctx.
type Backend interface {
	Initialize() error
	Finalize() error
	GetInfo() (pkcs11.Info, error)
	GetSlotList(bool) ([]uint, error)
	GetSlotInfo(uint) (pkcs11.SlotInfo, error)
	GetTokenInfo(uint) (pkcs11.TokenInfo, error)
	OpenSession(uint, uint) (pkcs11.SessionHandle, error)
	Login(pkcs11.SessionHandle, uint, string) error
	GetObjectSize(pkcs11.SessionHandle, pkcs11.ObjectHandle) (uint, error)
	GetAttributeValue(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error)
	FindObjectsInit(pkcs11.SessionHandle, []*pkcs11.Attribute) error
	FindObjects(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error)
}
