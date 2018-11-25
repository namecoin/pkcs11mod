// Copyright 2018 Namecoin Developers GPLv3+

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
}
