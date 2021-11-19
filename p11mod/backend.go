// Copyright 2021 Namecoin Developers LGPLv3+

package p11mod

import (
	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

// Backend is an interface compatible with p11.Module.
// TODO: Upstream this to miekg.
type Backend interface {
	Info() (pkcs11.Info, error)
	Slots() ([]Slot, error)
}

type Slot interface {
	ID() uint
	Info() (pkcs11.SlotInfo, error)
	TokenInfo() (pkcs11.TokenInfo, error)
	OpenSession() (p11.Session, error)
	OpenWriteSession() (p11.Session, error)
}
