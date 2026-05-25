// pkcs11mod
// Copyright (C) 2018-2025 Namecoin Developers
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
	"bytes"
	"crypto/sha1" //nolint:gosec // TODO: file bug with Mozilla about SHA1 stupidity
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"log"
	"math/big"
	"os"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"

	"github.com/namecoin/pkcs11mod"
)

func Slot(b Backend, id uint) p11.Slot {
	return &slot{
		trace:          os.Getenv("P11TRUSTMOD_TRACE") == "1",
		traceSensitive: os.Getenv("P11TRUSTMOD_TRACE_SENSITIVE") == "1",

		highBackend: b,
		slotID:      id,
	}
}

type slot struct {
	trace          bool
	traceSensitive bool

	highBackend Backend
	slotID      uint
}

type session struct {
	slot *slot
}

type builtinObject struct{}

type certificateObject struct {
	data                 *CertificateData
	includeBuiltinPolicy bool
}

type trustObject struct {
	data *CertificateData
}

func (s *slot) CloseAllSessions() error {
	return nil
}

func (s *slot) ID() uint {
	return s.slotID
}

func (s *slot) Info() (pkcs11.SlotInfo, error) {
	return s.highBackend.Info()
}

func (s *slot) InitToken(securityOfficerPIN, tokenLabel string) error {
	return pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

func (s *slot) Mechanisms() ([]p11.Mechanism, error) {
	return []p11.Mechanism{}, nil
}

// TODO: Remove this from the p11 interface.
func (s *slot) OpenSession() (p11.Session, error) {
	return &session{
		slot: s,
	}, nil
}

func (s *slot) OpenSessionWithFlags(flags uint) (p11.Session, error) {
	if flags&pkcs11.CKF_RW_SESSION != 0 {
		return s.OpenWriteSession()
	}

	return s.OpenSession()
}

// TODO: Remove this from the p11 interface.
func (s *slot) OpenWriteSession() (p11.Session, error) {
	return nil, pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

func (s *slot) TokenInfo() (pkcs11.TokenInfo, error) {
	return s.highBackend.TokenInfo()
}

// TODO: Remove this from the p11 interface.
func (s *session) Login(pin string) error {
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

// TODO: Remove this from the p11 interface.
func (s *session) LoginSecurityOfficer(pin string) error {
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (s *session) LoginAs(userType uint, pin string) error {
	return nil
}

func (s *session) Logout() error {
	return nil
}

func (s *session) Close() error {
	return nil
}

func (s *session) CreateObject(template []*pkcs11.Attribute) (p11.Object, error) {
	return nil, pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

// TODO: Remove this from the p11 interface.
func (s *session) FindObject(template []*pkcs11.Attribute) (p11.Object, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func extractSearchCertificate(attrVal []byte) *x509.Certificate {
	searchCertificate, err := x509.ParseCertificate(attrVal)
	if err != nil {
		// Invalid cert; ignore
		return nil
	}

	return searchCertificate
}

func extractSearchPKIXName(attrVal []byte) *pkix.Name {
	var subjectRDN pkix.RDNSequence

	if subjectRest, err := asn1.Unmarshal(attrVal, &subjectRDN); err != nil {
		log.Printf("p11trustmod FindObjects: Error unmarshaling X.509 subject/issuer: %s\n", err)
		return nil
	} else if len(subjectRest) != 0 {
		log.Println("p11trustmod FindObjects: Trailing data after X.509 subject/issuer")
		return nil
	}

	searchSubject := &pkix.Name{}
	searchSubject.FillFromRDNSequence(&subjectRDN)

	return searchSubject
}

func extractSearchSerial(attrVal []byte) *big.Int {
	var searchSerial *big.Int

	// Yes, we pass a pointer to a pointer to Unmarshal, see https://stackoverflow.com/questions/53139020/why-is-unmarshalling-of-a-der-asn-1-large-integer-limited-to-sequence-in-golang
	serialRest, err := asn1.Unmarshal(attrVal, &searchSerial)
	if err != nil {
		log.Printf("p11trustmod FindObjects: Error unmarshaling X.509 serial number: %s\n", err)

		return nil
	} else if len(serialRest) != 0 {
		log.Println("p11trustmod FindObjects: Trailing data after X.509 serial number")

		return nil
	}

	return searchSerial
}

func extractSearch(template []*pkcs11.Attribute) (*x509.Certificate, *pkix.Name, *pkix.Name, *big.Int) {
	var (
		searchCertificate *x509.Certificate
		searchSubject     *pkix.Name
		searchIssuer      *pkix.Name
		searchSerial      *big.Int
	)

	for _, attr := range template {
		if searchCertificate == nil && attr.Type == pkcs11.CKA_VALUE {
			searchCertificate = extractSearchCertificate(attr.Value)
		}

		if searchSubject == nil && attr.Type == pkcs11.CKA_SUBJECT {
			searchSubject = extractSearchPKIXName(attr.Value)
		}

		if searchIssuer == nil && attr.Type == pkcs11.CKA_ISSUER {
			searchIssuer = extractSearchPKIXName(attr.Value)
		}

		if searchSerial == nil && attr.Type == pkcs11.CKA_SERIAL_NUMBER {
			searchSerial = extractSearchSerial(attr.Value)
		}
	}

	return searchCertificate, searchSubject, searchIssuer, searchSerial
}

func (s *session) objectsFromCertificates(candidateCertificates []*CertificateData) ([]p11.Object, error) {
	includeBuiltin, err := s.slot.highBackend.IsBuiltinRootList()
	if err != nil {
		return []p11.Object{}, err
	}

	isTrusted, err := s.slot.highBackend.IsTrusted()
	if err != nil {
		return []p11.Object{}, err
	}

	candidateObjects := []p11.Object{}

	if includeBuiltin {
		candidateObjects = append(candidateObjects, &builtinObject{})
	}

	for _, cert := range candidateCertificates {
		if cert.Certificate.Raw != nil {
			// Don't return a certificate object if we don't have the full
			// certificate. This might be the case if we're trying to revoke a
			// certificate based on only its issuer+serial.
			candidateObjects = append(candidateObjects, &certificateObject{
				data:                 cert,
				includeBuiltinPolicy: includeBuiltin,
			})
		}

		if isTrusted {
			// Don't return a trust object if the trust attributes aren't set.
			// Otherwise, Firefox will treat the cert as explicitly distrusted.
			// Yes, I know the docs say CKT_NSS_TRUST_UNKNOWN will work fine.
			// The docs are wrong.
			if cert.TrustServerAuth != 0 || cert.TrustClientAuth != 0 || cert.TrustCodeSigning != 0 || cert.TrustEmailProtection != 0 {
				candidateObjects = append(candidateObjects, &trustObject{
					data: cert,
				})
			}
		}
	}

	return candidateObjects, nil
}

func (s *session) FindObjects(template []*pkcs11.Attribute) ([]p11.Object, error) {
	if s.slot.trace {
		log.Println("p11trustmod FindObjects: QueryAll")
	}

	candidateCertificates, err := s.slot.highBackend.QueryAll()
	if err != nil {
		return []p11.Object{}, err
	}

	searchCertificate, searchSubject, searchIssuer, searchSerial := extractSearch(template)

	if searchCertificate != nil {
		if s.slot.trace {
			if s.slot.traceSensitive {
				log.Printf("p11trustmod FindObjects: QueryCertificate: %v\n", searchCertificate.Raw)
			} else {
				log.Println("p11trustmod FindObjects: QueryCertificate")
			}
		}

		searchCertificateResults, err := s.slot.highBackend.QueryCertificate(searchCertificate)
		if err != nil {
			return []p11.Object{}, err
		}

		candidateCertificates = append(candidateCertificates, searchCertificateResults...)
	}

	if searchSubject != nil {
		if s.slot.trace {
			if s.slot.traceSensitive {
				log.Printf("p11trustmod FindObjects: QuerySubject: %s\n", searchSubject)
			} else {
				log.Println("p11trustmod FindObjects: QuerySubject")
			}
		}

		searchSubjectResults, err := s.slot.highBackend.QuerySubject(searchSubject)
		if err != nil {
			return []p11.Object{}, err
		}

		candidateCertificates = append(candidateCertificates, searchSubjectResults...)
	}

	if searchIssuer != nil || searchSerial != nil {
		if s.slot.trace {
			if s.slot.traceSensitive {
				log.Printf("p11trustmod FindObjects: QueryIssuerSerial: %s, CertSerialNumber=0x%s\n", searchIssuer, searchSerial.Text(16))
			} else {
				log.Println("p11trustmod FindObjects: QueryIssuerSerial")
			}
		}

		searchIssuerSerialResults, err := s.slot.highBackend.QueryIssuerSerial(searchIssuer, searchSerial)
		if err != nil {
			return []p11.Object{}, err
		}

		candidateCertificates = append(candidateCertificates, searchIssuerSerialResults...)
	}

	candidateObjects, err := s.objectsFromCertificates(candidateCertificates)
	if err != nil {
		return []p11.Object{}, err
	}

	result := []p11.Object{}

	if s.slot.trace {
		log.Printf("p11trustmod FindObjects: Object cache size: %d\n", len(candidateObjects))
	}

	for _, obj := range candidateObjects {
		if s.slot.checkObjectTemplate(obj, template) && checkValueUnique(obj, result) {
			result = append(result, obj)
		}
	}

	if s.slot.trace {
		log.Printf("p11trustmod FindObjects: Returned %d objects\n", len(result))
	}

	return result, nil
}

func (s *session) GenerateKeyPair(request p11.GenerateKeyPairRequest) (*p11.KeyPair, error) {
	return nil, pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

func (s *session) GenerateRandom(length int) ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_RANDOM_NO_RNG)
}

func (s *session) InitPIN(pin string) error {
	return pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

func (s *session) SetPIN(oldpin, newpin string) error {
	return pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

// checkObjectTemplate returns true if the object matches the template.
func (s *slot) checkObjectTemplate(obj p11.Object, template []*pkcs11.Attribute) bool {
	for _, tempAttr := range template {
		objData, err := obj.Attribute(tempAttr.Type)
		if err != nil {
			log.Printf("p11trustmod: Rejected object, missing attribute: %s\n", pkcs11mod.AttrTrace(tempAttr))
			return false
		}

		tempData := tempAttr.Value

		if !bytes.Equal(objData, tempData) {
			if s.trace {
				log.Printf("p11trustmod: Rejected object, non-matching attribute: template %s, object %s\n",
					pkcs11mod.AttrTrace(tempAttr),
					pkcs11mod.AttrTrace(&pkcs11.Attribute{Type: tempAttr.Type, Value: objData}))
			}

			return false
		}
	}

	return true
}

// checkValueUnique returns true if the object is not in the existing slice.
// Required because NSS seems to get unhappy (stops querying objects) if
// multiple object handles point to the same certificate.
// TODO: Make p11mod filter duplicates via reflect.DeepEqual, then we can remove this function.
func checkValueUnique(obj p11.Object, existing []p11.Object) bool {
	// TODO: Use obj.Value() once p11mod supports it.
	objValue, err := obj.Attribute(pkcs11.CKA_VALUE)
	if err != nil {
		log.Printf("p11trustmod: Rejected object, couldn't read value: %s\n", err)
		return false
	}

	for _, eObj := range existing {
		// TODO: Use eObj.Value() once p11mod supports it.
		eValue, err := eObj.Attribute(pkcs11.CKA_VALUE)
		if err != nil {
			log.Printf("p11trustmod: Rejected object, couldn't read previous value: %s\n", err)
			return false
		}

		if bytes.Equal(objValue, eValue) {
			return false
		}
	}

	return true
}

func marshalAttributeValue(x interface{}) []byte {
	a := pkcs11.NewAttribute(1, x)
	return a.Value
}

var builtinAttrConsts = map[uint]interface{}{
	pkcs11.CKA_CLASS:      uint(pkcs11.CKO_NSS_BUILTIN_ROOT_LIST),
	pkcs11.CKA_TOKEN:      true,
	pkcs11.CKA_PRIVATE:    false,
	pkcs11.CKA_MODIFIABLE: false,
	pkcs11.CKA_LABEL:      "Mozilla Builtin Roots",
}

func (obj *builtinObject) Attribute(attributeType uint) ([]byte, error) {
	constResult, ok := builtinAttrConsts[attributeType]
	if ok {
		return marshalAttributeValue(constResult), nil
	}

	log.Printf("p11trustmod Builtin Attribute: unexpected type: %d\n", attributeType)

	return nil, nil
}

func (obj *builtinObject) Copy(template []*pkcs11.Attribute) (p11.Object, error) {
	return nil, pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

func (obj *builtinObject) Destroy() error {
	return pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

// TODO: Remove this from the p11 interface.
func (obj *builtinObject) Label() (string, error) {
	return "", pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (obj *builtinObject) Set(attributeType uint, value []byte) error {
	return pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

// TODO: Remove this from the p11 interface.
func (obj *builtinObject) Value() ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (obj *builtinObject) PrivateKey() p11.PrivateKey {
	return nil
}

func (obj *builtinObject) PublicKey() p11.PublicKey {
	return nil
}

func (obj *builtinObject) SecretKey() p11.SecretKey {
	return nil
}

var certificateAttrConsts = map[uint]interface{}{
	pkcs11.CKA_CLASS:            uint(pkcs11.CKO_CERTIFICATE),
	pkcs11.CKA_TOKEN:            true,
	pkcs11.CKA_PRIVATE:          false,
	pkcs11.CKA_MODIFIABLE:       false,
	pkcs11.CKA_CERTIFICATE_TYPE: pkcs11.CKC_X_509,
	pkcs11.CKA_ID:               "0",
}

// TODO: Patch p11 to avoid marshalAttributeValue here.
func (obj *certificateObject) Attribute(attributeType uint) ([]byte, error) {
	switch attributeType {
	case pkcs11.CKA_LABEL:
		return marshalAttributeValue(obj.data.Label), nil
	case pkcs11.CKA_SUBJECT:
		if obj.data.Certificate.RawSubject != nil {
			return marshalAttributeValue(obj.data.Certificate.RawSubject), nil
		}

		rawSubject, err := asn1.Marshal(obj.data.Certificate.Subject.ToRDNSequence())
		if err != nil {
			log.Printf("p11trustmod Certificate Attribute: Error marshaling Subject: %s\n", err)
			// We treat an unmarshalable subject as a nonexistent attribute.
			return nil, nil
		}

		return marshalAttributeValue(rawSubject), nil
	case pkcs11.CKA_ISSUER:
		if obj.data.Certificate.RawIssuer != nil {
			return marshalAttributeValue(obj.data.Certificate.RawIssuer), nil
		}

		rawIssuer, err := asn1.Marshal(obj.data.Certificate.Issuer.ToRDNSequence())
		if err != nil {
			log.Printf("p11trustmod Certificate Attribute: Error marshaling Issuer: %s\n", err)
			// We treat an unmarshalable issuer as a nonexistent attribute.
			return nil, nil
		}

		return marshalAttributeValue(rawIssuer), nil
	case pkcs11.CKA_SERIAL_NUMBER:
		asn1SerialNumber, err := asn1.Marshal(obj.data.Certificate.SerialNumber)
		if err != nil {
			log.Printf("p11trustmod Certificate Attribute: Error marshaling SerialNumber: %s\n", err)
			// We treat an unmarshalable serial number as a nonexistent attribute.
			return nil, nil
		}

		return marshalAttributeValue(asn1SerialNumber), nil
	case pkcs11.CKA_VALUE:
		return marshalAttributeValue(obj.data.Certificate.Raw), nil
	case pkcs11.CKA_TRUSTED:
		return marshalAttributeValue(obj.data.Trusted), nil
	case pkcs11.CKA_NSS_MOZILLA_CA_POLICY:
		if obj.includeBuiltinPolicy {
			return marshalAttributeValue(obj.data.BuiltinPolicy), nil
		}

		return nil, nil
	// TODO: Support the DISTRUST_AFTER attributes properly.
	case pkcs11.CKA_NSS_SERVER_DISTRUST_AFTER:
		log.Printf("p11trustmod Certificate Attribute: unsupported type: CKA_NSS_SERVER_DISTRUST_AFTER\n")

		return marshalAttributeValue(false), nil
	case pkcs11.CKA_NSS_EMAIL_DISTRUST_AFTER:
		log.Printf("p11trustmod Certificate Attribute: unsupported type: CKA_NSS_EMAIL_DISTRUST_AFTER\n")

		return marshalAttributeValue(false), nil
	default:
		constResult, ok := certificateAttrConsts[attributeType]
		if ok {
			return marshalAttributeValue(constResult), nil
		}

		log.Printf("p11trustmod Certificate Attribute: unexpected type: %d\n", attributeType)

		return nil, nil
	}
}

func (obj *certificateObject) Copy(template []*pkcs11.Attribute) (p11.Object, error) {
	return nil, pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

func (obj *certificateObject) Destroy() error {
	return pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

// TODO: Remove this from the p11 interface.
func (obj *certificateObject) Label() (string, error) {
	return "", pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (obj *certificateObject) Set(attributeType uint, value []byte) error {
	return pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

// TODO: Remove this from the p11 interface.
func (obj *certificateObject) Value() ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (obj *certificateObject) PrivateKey() p11.PrivateKey {
	return nil
}

func (obj *certificateObject) PublicKey() p11.PublicKey {
	return nil
}

func (obj *certificateObject) SecretKey() p11.SecretKey {
	return nil
}

var trustAttrConsts = map[uint]interface{}{
	pkcs11.CKA_CLASS:      uint(pkcs11.CKO_NSS_TRUST),
	pkcs11.CKA_TOKEN:      true,
	pkcs11.CKA_PRIVATE:    false,
	pkcs11.CKA_MODIFIABLE: false,
	// According to "certutil --help", "make step-up cert" is the description
	// of the "g" trust attribute.  According to the NSS
	// "CERT_DecodeTrustString" function, the "g" trust attribute corresponds
	// to the "CERTDB_GOVT_APPROVED_CA" flag.  The #define for
	// "CERTDB_GOVT_APPROVED_CA" includes the comment "can do strong crypto in
	// export ver".  So, I infer that "step-up" refers to some kind of
	// governmental regulatory approval involving crypto export controls.
	// According to "certdata.txt" in Mozilla's Mercurial repo, all of the CKBI
	// CA's have this attribute set to false.
	pkcs11.CKA_TRUST_STEP_UP_APPROVED: false,
}

func marshalCKTValue(ckt interface{}) []byte {
	if ckt == 0 {
		return marshalAttributeValue(uint(pkcs11.CKT_NSS_TRUST_UNKNOWN))
	}

	return marshalAttributeValue(ckt)
}

func (obj *trustObject) Attribute(attributeType uint) ([]byte, error) {
	switch attributeType {
	case pkcs11.CKA_LABEL:
		return marshalAttributeValue(obj.data.Label), nil
	case pkcs11.CKA_CERT_SHA1_HASH:
		if obj.data.Certificate.Raw == nil {
			// Don't return a certificate hash we don't have the full
			// certificate. This might be the case if we're trying to revoke a
			// certificate based on only its issuer+serial.
			return nil, nil
		}

		// Yes, NSS is a pile of fail and uses SHA1 to identify
		// certificates.  They should probably fix this in the
		// future.  TODO: File bug with Mozilla.
		//nolint:gosec
		sha1Array := sha1.Sum(obj.data.Certificate.Raw)

		return marshalAttributeValue(sha1Array[:]), nil
	case pkcs11.CKA_ISSUER:
		if obj.data.Certificate.RawIssuer != nil {
			return marshalAttributeValue(obj.data.Certificate.RawIssuer), nil
		}

		rawIssuer, err := asn1.Marshal(obj.data.Certificate.Issuer.ToRDNSequence())
		if err != nil {
			log.Printf("p11trustmod Certificate Attribute: Error marshaling Issuer: %s\n", err)
			// We treat an unmarshalable issuer as a nonexistent attribute.
			return nil, nil
		}

		return marshalAttributeValue(rawIssuer), nil
	case pkcs11.CKA_SERIAL_NUMBER:
		asn1SerialNumber, err := asn1.Marshal(obj.data.Certificate.SerialNumber)
		if err != nil {
			log.Printf("p11trustmod Trust Attribute: Error marshaling SerialNumber: %s\n", err)
			// We treat an unmarshalable serial number as a nonexistent attribute.
			return nil, nil
		}

		return marshalAttributeValue(asn1SerialNumber), nil
	case pkcs11.CKA_TRUST_SERVER_AUTH:
		return marshalCKTValue(obj.data.TrustServerAuth), nil
	case pkcs11.CKA_TRUST_CLIENT_AUTH:
		return marshalCKTValue(obj.data.TrustClientAuth), nil
	case pkcs11.CKA_TRUST_CODE_SIGNING:
		return marshalCKTValue(obj.data.TrustCodeSigning), nil
	case pkcs11.CKA_TRUST_EMAIL_PROTECTION:
		return marshalCKTValue(obj.data.TrustEmailProtection), nil
	default:
		constResult, ok := trustAttrConsts[attributeType]
		if ok {
			return marshalAttributeValue(constResult), nil
		}

		log.Printf("p11trustmod Trust Attribute: unexpected type: %d\n", attributeType)

		return nil, nil
	}
}

func (obj *trustObject) Copy(template []*pkcs11.Attribute) (p11.Object, error) {
	return nil, pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

func (obj *trustObject) Destroy() error {
	return pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

// TODO: Remove this from the p11 interface.
func (obj *trustObject) Label() (string, error) {
	return "", pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (obj *trustObject) Set(attributeType uint, value []byte) error {
	return pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

// TODO: Remove this from the p11 interface.
func (obj *trustObject) Value() ([]byte, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (obj *trustObject) PrivateKey() p11.PrivateKey {
	return nil
}

func (obj *trustObject) PublicKey() p11.PublicKey {
	return nil
}

func (obj *trustObject) SecretKey() p11.SecretKey {
	return nil
}
