// Copyright 2018 Namecoin Developers LGPLv3+

package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"log"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/pkcs11"

	"github.com/namecoin/ncp11/pkcs11mod"
)

// These are NSS-specific pkcs11 constants.
// TODO: check with miekg whether he'd accept a PR to add them to miekg/pkcs11.
const (
	CKA_TRUST_SERVER_AUTH      uint = 0xce536358
	CKA_TRUST_CLIENT_AUTH      uint = 0xce536359
	CKA_TRUST_CODE_SIGNING     uint = 0xce53635a
	CKA_TRUST_EMAIL_PROTECTION uint = 0xce53635b
	CKA_TRUST_STEP_UP_APPROVED uint = 0xce536360
	CKA_CERT_SHA1_HASH         uint = 0xce5363b4
	CKO_NSS_TRUST              uint = 0xce534353
	CKT_NSS_TRUSTED            uint = 0xce534351
	CKT_NSS_TRUSTED_DELEGATOR  uint = 0xce534352
	CKT_NSS_NOT_TRUSTED        uint = 0xce53435A
	CKT_NSS_TRUST_UNKNOWN      uint = 0xce534355
)

type certObject struct {
	cert *x509.Certificate
	class uint
}

type session struct {
	certs chan *certObject
	domain string
	template []*pkcs11.Attribute
	objects []*certObject // The ObjectHandle is calculated as the index in this slice + 1
	// TODO: make object handles unique per token, not just unique per session.
	// TODO: delete object handles that are outdated, so that we can be guaranteed that revocation works
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
		Model: "ncp11",
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
	log.Printf("GetObjectSize unimplemented\n")
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (b BackendNamecoin) GetAttributeValue(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	b.sessionMutex.RLock()
	s, sessionExists := b.sessions[sh]
	b.sessionMutex.RUnlock()

	if !sessionExists {
		return nil, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	co := s.objects[oh - 1]
	cert := co.cert

	results := make([]*pkcs11.Attribute, len(a))

	hasUnknownAttr := false
	unknownAttrs := []uint{}

	for i, attr := range a {
		if attr.Type == pkcs11.CKA_CLASS {
			results[i] = pkcs11.NewAttribute(attr.Type, co.class)
		} else if attr.Type == pkcs11.CKA_TOKEN {
			results[i] = pkcs11.NewAttribute(attr.Type, true)
		} else if attr.Type == pkcs11.CKA_LABEL {
			fingerprintArray := sha256.Sum256(cert.Raw)
			hexFingerprint := strings.ToUpper(hex.EncodeToString(fingerprintArray[:]))

			results[i] = pkcs11.NewAttribute(attr.Type, cert.Subject.CommonName + " " + hexFingerprint)
		} else if attr.Type == pkcs11.CKA_VALUE {
			results[i] = pkcs11.NewAttribute(attr.Type, cert.Raw)
		} else if attr.Type == pkcs11.CKA_CERTIFICATE_TYPE {
			results[i] = pkcs11.NewAttribute(attr.Type, pkcs11.CKC_X_509)
		} else if attr.Type == pkcs11.CKA_ISSUER {
			results[i] = pkcs11.NewAttribute(attr.Type, cert.RawIssuer)
		} else if attr.Type == pkcs11.CKA_SERIAL_NUMBER {
			certSerialNumber, err := asn1.Marshal(cert.SerialNumber)
			if err != nil {
				log.Printf("Error marshaling SerialNumber from dehydrated cert")
				hasUnknownAttr = true
				unknownAttrs = append(unknownAttrs, attr.Type)
			}

			results[i] = pkcs11.NewAttribute(attr.Type, certSerialNumber)
		} else if attr.Type == pkcs11.CKA_SUBJECT {
			results[i] = pkcs11.NewAttribute(attr.Type, cert.RawSubject)
		} else if attr.Type == pkcs11.CKA_ID {
			results[i] = pkcs11.NewAttribute(attr.Type, "0")
		} else if attr.Type == CKA_TRUST_SERVER_AUTH {
			// CKT_NSS_TRUSTED should be equivalent to the "P"
			// trust flag in NSS certutil.
			// TODO: actually test that CKT_NSS_TRUSTED doesn't
			// allow it to act as a CA.
			results[i] = pkcs11.NewAttribute(attr.Type, CKT_NSS_TRUSTED)
		} else if attr.Type == CKA_TRUST_CLIENT_AUTH {
			// CKT_NSS_NOT_TRUSTED should be equivalent to
			// blacklisting the cert.
			// TODO: actually test that the cert doesn't work for
			// that purpose.
			results[i] = pkcs11.NewAttribute(attr.Type, CKT_NSS_NOT_TRUSTED)
		} else if attr.Type == CKA_TRUST_CODE_SIGNING {
			// CKT_NSS_NOT_TRUSTED should be equivalent to
			// blacklisting the cert.
			// TODO: actually test that the cert doesn't work for
			// that purpose.
			results[i] = pkcs11.NewAttribute(attr.Type, CKT_NSS_NOT_TRUSTED)
		} else if attr.Type == CKA_TRUST_EMAIL_PROTECTION {
			// CKT_NSS_NOT_TRUSTED should be equivalent to
			// blacklisting the cert.
			// TODO: actually test that the cert doesn't work for
			// that purpose.
			results[i] = pkcs11.NewAttribute(attr.Type, CKT_NSS_NOT_TRUSTED)
		} else if attr.Type == CKA_TRUST_STEP_UP_APPROVED {
			// According to "certutil --help", "make step-up cert"
			// is the description of the "g" trust attribute.
			// According to the NSS "CERT_DecodeTrustString"
			// function, the "g" trust attribute corresponds to the
			// "CERTDB_GOVT_APPROVED_CA" flag.  The #define for
			// "CERTDB_GOVT_APPROVED_CA" includes the comment "can
			// do strong crypto in export ver".  So, I infer that
			// "step-up" refers to some kind of governmental
			// regulatory approval involving crypto export
			// controls.  According to "certdata.txt" in Mozilla's
			// Mercurial repo, all of the CKBI CA's have this
			// attribute set to false.
			results[i] = pkcs11.NewAttribute(attr.Type, false)
		} else if attr.Type == CKA_CERT_SHA1_HASH {
			// Yes, NSS is a pile of fail and uses SHA1 to identify
			// certificates.  They should probably fix this in the
			// future.
			sha1Array := sha1.Sum(cert.Raw)

			results[i] = pkcs11.NewAttribute(attr.Type, sha1Array[:])
		} else {
			results[i] = pkcs11.NewAttribute(attr.Type, nil)

			hasUnknownAttr = true
			unknownAttrs = append(unknownAttrs, attr.Type)
		}
	}

	if hasUnknownAttr {
		// We don't return CKR_ATTRIBUTE_TYPE_INVALID because that
		// would result in the application attempting to use the
		// results.
		log.Printf("GetAttributeValue requested unknown attribute types %v\n", unknownAttrs)
		return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
	}

	return results, nil
}

func (b BackendNamecoin) FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error {
	var attrTypes []uint
	recognizedTemplate := false
	foundName := false
	var domain string

	for _, attr := range temp {
		if attr.Type == pkcs11.CKA_ISSUER || attr.Type == pkcs11.CKA_SUBJECT {
			recognizedTemplate = true

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

			if dn2.SerialNumber == "Namecoin TLS Certificate" {
				domain = dn2.CommonName

				log.Printf("CommonName: %s\n", domain)

				foundName = true
			}
		}

		attrTypes = append(attrTypes, attr.Type)
	}

	b.sessionMutex.RLock()
	s, sessionExists := b.sessions[sh]
	b.sessionMutex.RUnlock()

	if !sessionExists {
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	if foundName {
		// We found the name, so we can start the certificate lookup
		// procedure.

		s.certs = make(chan *certObject)
		s.domain = domain
		s.template = temp

		go s.lookupCerts(s.certs)
	} else if recognizedTemplate {
		// The cert being queried isn't a Namecoin certificate, so
		// return an empty list.
		s.certs = make(chan *certObject)
		close(s.certs)
	} else if len(attrTypes) == 0 {
		// The application is requesting a complete list of all
		// Namecoin certificates.  We don't support this use case, so
		// we'll pretend that no certificates were found.  This variant
		// seems to show up from pkcs11-dump.
		s.certs = make(chan *certObject)
		close(s.certs)
	} else if len(attrTypes) == 1 && attrTypes[0] == pkcs11.CKA_CLASS {
		// Ditto.  This variant seems to show up from Chromium on
		// GNU/Linux during initial boot.
		s.certs = make(chan *certObject)
		close(s.certs)
	} else if len(attrTypes) == 2 && attrTypes[0] == pkcs11.CKA_ID && attrTypes[1] == pkcs11.CKA_CLASS {
		// Ditto.  This variant seems to show up from Chromium on
		// GNU/Linux during certificate validation.

		s.certs = make(chan *certObject)
		close(s.certs)
	} else {
		log.Printf("Unknown FindObjectsInit template types: %v\n", attrTypes)
		s.certs = make(chan *certObject)
		close(s.certs)
	}

	return nil
}

func (b BackendNamecoin) FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	b.sessionMutex.RLock()
	s, sessionExists := b.sessions[sh]
	b.sessionMutex.RUnlock()

	if !sessionExists {
		return []pkcs11.ObjectHandle{}, false, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	result := []pkcs11.ObjectHandle{}

	var co *certObject
	var ok bool

	for len(result) < max {
		co, ok = <- s.certs
		if !ok {
			break
		}

		if !certMatchesTemplate(co, s.template) {
			continue
		}

		s.objects = append(s.objects, co)
		result = append(result, pkcs11.ObjectHandle(len(s.objects)))
	}

	return result, false, nil
}

func (b BackendNamecoin) FindObjectsFinal(sh pkcs11.SessionHandle) error {
	// TODO: clean up any data created during the FindObjects operation

	return nil
}

func (s *session) lookupCerts(dest chan *certObject) {
	var netClient = &http.Client{
		Timeout: time.Second * 10,
	}

	postArgs := url.Values{}
	postArgs.Set("domain", s.domain)

	response, err := netClient.PostForm("http://127.0.0.1:8080/lookup", postArgs)
	if err != nil {
		close(dest)
		log.Printf("Error POSTing to cert API: %s\n", err)
		return
	}

	buf, err := ioutil.ReadAll(response.Body)
	if err != nil {
		close(dest)
		log.Printf("Error reading response from cert API: %s\n", err)
		return
	}

	err = response.Body.Close()
	if err != nil {
		close(dest)
		log.Printf("Error closing response from cert API: %s\n", err)
		return
	}

	var block *pem.Block
	for {
		block, buf = pem.Decode(buf)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		dest <- &certObject{
			cert: cert,
			class: pkcs11.CKO_CERTIFICATE,
		}

		dest <- &certObject{
			cert: cert,
			class: CKO_NSS_TRUST,
		}
	}

	close(dest)
}

func certMatchesTemplate(co *certObject, template []*pkcs11.Attribute) bool {
	cert := co.cert

	for _, attr := range template {
		if attr.Type == pkcs11.CKA_CLASS {
			templateClass, err := pkcs11mod.BytesToULong(attr.Value)
			if err != nil {
				log.Printf("Template contains invalid CKA_CLASS %v\n", attr.Value)
				return false
			}

			// The valid values expected by NSS seem to be:
			// CKO_CERTIFICATE and CKO_NSS_TRUST
			//
			// CKO_CERTIFICATE stores the certificate's contents,
			// as well as CKA_NSS_MOZILLA_CA_POLICY which is
			// relevant to HPKP enforcement.
			//
			// CKO_NSS_TRUST stores most of the certificate's trust
			// attributes.
			if templateClass == co.class {
				continue
			}

			if templateClass != pkcs11.CKO_CERTIFICATE && templateClass != CKO_NSS_TRUST {
				log.Printf("Template contains unknown CKA_CLASS %v\n", templateClass)
			}

			return false
		} else if attr.Type == pkcs11.CKA_TOKEN {
			// Only accept token objects
			templateIsToken, err := pkcs11mod.BytesToBool(attr.Value)
			if err != nil {
				log.Printf("Template contains invalid CKA_TOKEN %v\n", attr.Value)
				return false
			}

			if !templateIsToken {
				return false
			}
		} else if attr.Type == pkcs11.CKA_ISSUER {
			templateIssuer := attr.Value
			certIssuer := cert.RawIssuer

			if !bytes.Equal(certIssuer, templateIssuer) {
				return false
			}
		} else if attr.Type == pkcs11.CKA_SERIAL_NUMBER {
			templateSerialNumber := attr.Value
			certSerialNumber, err := asn1.Marshal(cert.SerialNumber)
			if err != nil {
				log.Printf("Error marshaling SerialNumber from dehydrated cert")
				return false
			}

			if !bytes.Equal(certSerialNumber, templateSerialNumber) {
				return false
			}
		} else if attr.Type == pkcs11.CKA_SUBJECT {
			templateSubject := attr.Value
			certSubject := cert.RawSubject

			if !bytes.Equal(certSubject, templateSubject) {
				return false
			}
		} else if attr.Type == pkcs11.CKA_ID {
			if !bytes.Equal([]byte("0"), attr.Value) {
				return false
			}
		} else {
			log.Printf("Template contains unknown attribute %v\n", attr.Type)
			return false
		}
	}

	return true
}
