// pkcs11mod
// Copyright (C) 2021  Namecoin Developers
//
// pkcs11mod is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// pkcs11mod is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with pkcs11mod; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

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
