// pkcs11mod
// Copyright (C) 2021-2022  Namecoin Developers
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

package p11trustmod

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	
	
	"github.com/miekg/pkcs11"
)

type Backend interface {
	// Metadata
	Info() (pkcs11.SlotInfo, error)
	TokenInfo() (pkcs11.TokenInfo, error)
	IsBuiltinRootList() (bool, error)
	IsTrusted() (bool, error)

	// Query
	// TODO: Add StreamIsolationID param, which resets to a new random number whenever an end-entity cert is queried from Tor Browser.
	QueryCertificate(*x509.Certificate) ([]*CertificateData, error)
	QuerySubject(*pkix.Name) ([]*CertificateData, error)
	QueryIssuerSerial(*pkix.Name, *big.Int) ([]*CertificateData, error)
	QueryAll() ([]*CertificateData, error)
}

type CertificateData struct {
	Label string
	Certificate *x509.Certificate
	BuiltinPolicy bool
	TrustServerAuth uint
	TrustClientAuth uint
	TrustCodeSigning uint
	TrustEmailProtection uint
}
