// Copyright 2018 Namecoin Developers LGPLv3+

package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"log"
	"sync"

	"github.com/miekg/pkcs11"
)

type session struct {
}

type BackendNamecoin struct {
	manufacturer string
	description string
	version pkcs11.Version
	slot uint
	sessions map[pkcs11.SessionHandle]*session
	sessionMutex sync.RWMutex // Used for the sessions var
}

func NewBackendNamecoin() BackendNamecoin {
	return BackendNamecoin{
		manufacturer: "Namecoin",
		description: "Namecoin TLS Certificate Trust",
		version: pkcs11.Version{0, 0},
		slot: 0,
		sessions: map[pkcs11.SessionHandle]*session{},
	}
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
		ManufacturerID:     b.manufacturer,
		Flags:              0,
		LibraryDescription: b.description,
		LibraryVersion:     b.version,
	}
	return info, nil
}

func (b BackendNamecoin) GetSlotList(tokenPresent bool) ([]uint, error) {
	// Only a single slot exists.
	return []uint{b.slot}, nil
}

func (b BackendNamecoin) GetSlotInfo(slotID uint) (pkcs11.SlotInfo, error) {
	if slotID != b.slot {
		return pkcs11.SlotInfo{}, pkcs11.Error(pkcs11.CKR_SLOT_ID_INVALID)
	}

	slotInfo := pkcs11.SlotInfo{
		SlotDescription: b.description,
		ManufacturerID: b.manufacturer,
		Flags: pkcs11.CKF_TOKEN_PRESENT,
		HardwareVersion: b.version,
		FirmwareVersion: b.version,
	}

	return slotInfo, nil
}

func (b BackendNamecoin) GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error) {
	if slotID != b.slot {
		return pkcs11.TokenInfo{}, pkcs11.Error(pkcs11.CKR_SLOT_ID_INVALID)
	}

	tokenInfo := pkcs11.TokenInfo{
		Label: b.description,
		ManufacturerID: b.manufacturer,
		Model: "nctls.so",
		SerialNumber: "1",
		Flags: pkcs11.CKF_WRITE_PROTECTED,
		MaxSessionCount: 0, // CK_EFFECTIVELY_INFINITE from pkcs11 spec (not in miekg/pkcs11)
		SessionCount: ^uint(0), // CK_UNAVAILABLE_INFORMATION from pkcs11 spec (not in miekg/pkcs11)
		MaxRwSessionCount: ^uint(0), // CK_UNAVAILABLE_INFORMATION from pkcs11 spec (not in miekg/pkcs11)
		RwSessionCount: ^uint(0), // CK_UNAVAILABLE_INFORMATION from pkcs11 spec (not in miekg/pkcs11)
		MaxPinLen: ^uint(0), // highest possible uint
		MinPinLen: 0,
		TotalPublicMemory: ^uint(0), // CK_UNAVAILABLE_INFORMATION from pkcs11 spec (not in miekg/pkcs11)
		FreePublicMemory: ^uint(0), // CK_UNAVAILABLE_INFORMATION from pkcs11 spec (not in miekg/pkcs11)
		TotalPrivateMemory: ^uint(0), // CK_UNAVAILABLE_INFORMATION from pkcs11 spec (not in miekg/pkcs11)
		FreePrivateMemory: ^uint(0), // CK_UNAVAILABLE_INFORMATION from pkcs11 spec (not in miekg/pkcs11)
		HardwareVersion: b.version,
		FirmwareVersion: b.version,
		UTCTime: "",
	}

	return tokenInfo, nil
}

func (b BackendNamecoin) GetMechanismList(slotID uint) ([]*pkcs11.Mechanism, error) {
	// Namecoin doesn't implement any mechanisms
	return []*pkcs11.Mechanism{}, nil
}

// Only call this while b.sessionMutex is write-locked
func (b BackendNamecoin) nextAvailableSessionHandle() pkcs11.SessionHandle {
	sessionHandle := pkcs11.SessionHandle(1)

	for _, ok := b.sessions[sessionHandle]; ok; sessionHandle++ {
	}

	return sessionHandle
}

func (b BackendNamecoin) OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error) {
	if slotID != b.slot {
		return 0, pkcs11.Error(pkcs11.CKR_SLOT_ID_INVALID)
	}

	if flags & pkcs11.CKF_RW_SESSION != 0 {
		// only read-only sessions are supported.
		return 0, pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
	}
	if flags & pkcs11.CKF_SERIAL_SESSION == 0 {
		return 0, pkcs11.Error(pkcs11.CKR_SESSION_PARALLEL_NOT_SUPPORTED)
	}

	newSession := session{}

	b.sessionMutex.Lock()
	newSessionHandle := b.nextAvailableSessionHandle()
	b.sessions[newSessionHandle] = &newSession
	b.sessionMutex.Unlock()

	return newSessionHandle, nil
}

func (b BackendNamecoin) CloseSession(sh pkcs11.SessionHandle) error {
	b.sessionMutex.Lock()
	_, sessionExists := b.sessions[sh]
	delete(b.sessions, sh)
	b.sessionMutex.Unlock()

	if !sessionExists {
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	return nil
}

func (b BackendNamecoin) Login(sh pkcs11.SessionHandle, userType uint, pin string) error {
	return nil
}

func (b BackendNamecoin) Logout(sh pkcs11.SessionHandle) error {
	return nil
}

func (b BackendNamecoin) GetObjectSize(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) (uint, error) {
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b BackendNamecoin) GetAttributeValue(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b BackendNamecoin) FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error {
	var attrTypes []uint
	foundName := false

	for _, attr := range temp {
		if attr.Type == pkcs11.CKA_ISSUER || attr.Type == pkcs11.CKA_SUBJECT {
			var dn1 pkix.RDNSequence
			if rest, err := asn1.Unmarshal(attr.Value, &dn1); err != nil {
				log.Printf("Error unmarshaling X.509 issuer or subject: %v\n", err)
				continue
			} else if len(rest) != 0 {
				log.Printf("Error: trailing data after X.509 issuer or subject\n")
				continue
			}

			var dn2 pkix.Name
			dn2.FillFromRDNSequence(&dn1)

			log.Printf("CommonName: %s\n", dn2.CommonName)
		}

		attrTypes = append(attrTypes, attr.Type)
	}

	if foundName {
		// We found the name, so we can start the certificate lookup
		// procedure.
	} else if len(attrTypes) == 0 {
		// The application is requesting a complete list of all
		// Namecoin certificates.  We don't support this use case, so
		// we'll pretend that no certificates were found.  This variant
		// seems to show up from pkcs11-dump.
	} else if len(attrTypes) == 1 && attrTypes[0] == pkcs11.CKA_CLASS {
		// Ditto.  This variant seems to show up from Chromium on
		// GNU/Linux.
	} else {
		log.Printf("Unknown FindObjectsInit template types: %v\n", attrTypes)
	}

	// TODO: implement this for known-usable templates

	return nil
}

func (b BackendNamecoin) FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	// TODO: implement this for known-usable templates

	return []pkcs11.ObjectHandle{}, false, nil
}

func (b BackendNamecoin) FindObjectsFinal(sh pkcs11.SessionHandle) error {
	// TODO: clean up any data created during the FindObjects operation

	return nil
}
