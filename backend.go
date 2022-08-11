// pkcs11mod
// Copyright (C) 2018-2022  Namecoin Developers
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

package pkcs11mod

import (
	"github.com/miekg/pkcs11"
)

// Backend is an interface compatible with *pkcs11.Ctx.
type Backend interface {
	Initialize() error
	Finalize() error
	GetInfo() (pkcs11.Info, error)
	GetSlotList(bool) ([]uint, error)
	GetSlotInfo(uint) (pkcs11.SlotInfo, error)
	GetTokenInfo(uint) (pkcs11.TokenInfo, error)
	GetMechanismList(uint) ([]*pkcs11.Mechanism, error)
	GetMechanismInfo(uint, []*pkcs11.Mechanism) (pkcs11.MechanismInfo, error)
	InitPIN(pkcs11.SessionHandle, string) error
	SetPIN(pkcs11.SessionHandle, string, string) error
	OpenSession(uint, uint) (pkcs11.SessionHandle, error)
	CloseSession(pkcs11.SessionHandle) error
	CloseAllSessions(uint) error
	GetSessionInfo(pkcs11.SessionHandle) (pkcs11.SessionInfo, error)
	GetOperationState(pkcs11.SessionHandle) ([]byte, error)
	SetOperationState(pkcs11.SessionHandle, []byte, pkcs11.ObjectHandle, pkcs11.ObjectHandle) error
	Login(pkcs11.SessionHandle, uint, string) error
	Logout(pkcs11.SessionHandle) error
	CreateObject(pkcs11.SessionHandle, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	CopyObject(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	DestroyObject(pkcs11.SessionHandle, pkcs11.ObjectHandle) error
	GetObjectSize(pkcs11.SessionHandle, pkcs11.ObjectHandle) (uint, error)
	GetAttributeValue(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error)
	SetAttributeValue(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) error
	FindObjectsInit(pkcs11.SessionHandle, []*pkcs11.Attribute) error
	FindObjects(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error)
	FindObjectsFinal(pkcs11.SessionHandle) error
	EncryptInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error
	Encrypt(pkcs11.SessionHandle, []byte) ([]byte, error)
	EncryptUpdate(pkcs11.SessionHandle, []byte) ([]byte, error)
	EncryptFinal(pkcs11.SessionHandle) ([]byte, error)
	DecryptInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error
	Decrypt(pkcs11.SessionHandle, []byte) ([]byte, error)
	DecryptUpdate(pkcs11.SessionHandle, []byte) ([]byte, error)
	DecryptFinal(pkcs11.SessionHandle) ([]byte, error)
	DigestInit(pkcs11.SessionHandle, []*pkcs11.Mechanism) error
	Digest(pkcs11.SessionHandle, []byte) ([]byte, error)
	DigestUpdate(pkcs11.SessionHandle, []byte) error
	DigestKey(pkcs11.SessionHandle, pkcs11.ObjectHandle) error
	DigestFinal(pkcs11.SessionHandle) ([]byte, error)
	SignInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error
	Sign(pkcs11.SessionHandle, []byte) ([]byte, error)
	SignUpdate(pkcs11.SessionHandle, []byte) error
	SignFinal(pkcs11.SessionHandle) ([]byte, error)
	SignRecoverInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error
	SignRecover(pkcs11.SessionHandle, []byte) ([]byte, error)
	VerifyInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error
	Verify(pkcs11.SessionHandle, []byte, []byte) error
	VerifyUpdate(pkcs11.SessionHandle, []byte) error
	VerifyFinal(pkcs11.SessionHandle, []byte) error
	VerifyRecoverInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error
	VerifyRecover(pkcs11.SessionHandle, []byte) ([]byte, error)
	DigestEncryptUpdate(pkcs11.SessionHandle, []byte) ([]byte, error)
	DecryptDigestUpdate(pkcs11.SessionHandle, []byte) ([]byte, error)
	SignEncryptUpdate(pkcs11.SessionHandle, []byte) ([]byte, error)
	DecryptVerifyUpdate(pkcs11.SessionHandle, []byte) ([]byte, error)
	GenerateKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	GenerateKeyPair(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error)
	WrapKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, pkcs11.ObjectHandle) ([]byte, error)
	UnwrapKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, []byte, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	DeriveKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	SeedRandom(pkcs11.SessionHandle, []byte) error
	GenerateRandom(pkcs11.SessionHandle, int) ([]byte, error)
	WaitForSlotEvent(uint) chan pkcs11.SlotEvent
}
