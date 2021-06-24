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
	Slots() ([]p11.Slot, error)
}
