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

package p11trustmod

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"log"
	"math/big"
	"sync"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"

	"github.com/namecoin/pkcs11mod/p11mod"
)

func Slot(b Backend, id uint) p11.Slot {
	return &slot{
		highBackend: b,
		slotID: id,
	}
}

type slot struct {
	highBackend Backend
	slotID uint
}

type session struct {
	slot *slot
}

type builtinObject struct {
}

type certificateObject struct {
	data *CertificateData
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

// TODO: Remove this from the p11 interface
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

// TODO: Remove this from the p11 interface
func (s *slot) OpenWriteSession() (p11.Session, error) {
	return nil, pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

func (s *slot) TokenInfo() (pkcs11.TokenInfo, error) {
	return s.highBackend.TokenInfo()
}

func (s *session) LoginAs(userType uint, pin string) error {
	return nil
}

func (s *session) Close() error {
	return nil
}

func (s *session) CreateObject(template []*pkcs11.Attribute) (p11.Object, error) {
	return nil, pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

// TODO: Remove this from the p11 interface
func (s *session) FindObject(template []*pkcs11.Attribute) (p11.Object, error) {
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (s *session) FindObjects(template []*pkcs11.Attribute) ([]p11.Object, error) {
	includeBuiltin, err := s.slot.highBackend.IsBuiltinRootList()
	if err != nil {
		return []p11.Object{}, err
	}

	isTrusted, err := s.slot.highBackend.IsTrusted()
	if err != nil {
		return []p11.Object{}, err
	}

	candidateCertificates, err := s.slot.highBackend.QueryAll()
	if err != nil {
		return []p11.Object{}, err
	}

	var searchCertificate *x509.Certificate
	var searchSubject *pkix.Name
	var searchIssuer *pkix.Name
	var searchSerial *big.Int

	for _, attr := range template {
		if searchCertificate == nil && attr.Type == pkcs11.CKA_VALUE {
			searchCertificate, err = x509.ParseCertificate(attr.Value)
			if err != nil {
				// Invalid cert; ignore
				searchCertificate = nil
				continue
			}
		}

		if searchSubject == nil && attr.Type == pkcs11.CKA_SUBJECT {
			var subjectRDN pkix.RDNSequence

			if subjectRest, err := asn1.Unmarshal(attr.Value, &subjectRDN); err != nil {
				log.Printf("Error unmarshaling X.509 subject: %v\n", err)
				continue
			} else if len(subjectRest) != 0 {
				log.Printf("Error: trailing data after X.509 subject\n")
				continue
			}

			searchSubject = &pkix.Name{}
			searchSubject.FillFromRDNSequence(&subjectRDN)
		}

		if searchIssuer == nil && attr.Type == pkcs11.CKA_ISSUER {
			var issuerRDN pkix.RDNSequence

			if issuerRest, err := asn1.Unmarshal(attr.Value, &issuerRDN); err != nil {
				log.Printf("Error unmarshaling X.509 issuer: %v\n", err)
				continue
			} else if len(issuerRest) != 0 {
				log.Printf("Error: trailing data after X.509 issuer\n")
				continue
			}

			searchIssuer = &pkix.Name{}
			searchIssuer.FillFromRDNSequence(&issuerRDN)
		}

		if searchSerial == nil && attr.Type == pkcs11.CKA_SERIAL_NUMBER {
			// Yes, we pass a pointer to a pointer to Unmarshal, see https://stackoverflow.com/questions/53139020/why-is-unmarshalling-of-a-der-asn-1-large-integer-limited-to-sequence-in-golang
			serialRest, err := asn1.Unmarshal(attr.Value, &searchSerial)
			if err != nil {
				log.Printf("Error unmarshaling X.509 serial number: %s", err)
				searchSerial = nil
				continue
			} else if len(serialRest) != 0 {
				log.Printf("Error: trailing data after X.509 serial number\n")
				searchSerial = nil
				continue
			}
		}
	}

	if searchCertificate != nil {
		searchCertificateResults, err := s.slot.highBackend.QueryCertificate(searchCertificate)
		if err != nil {
			return []p11.Object{}, err
		}

		candidateCertificates = append(candidateCertificates, searchCertificateResults...)
	}

	if searchSubject != nil {
		searchSubjectResults, err := s.slot.highBackend.QuerySubject(searchSubject)
		if err != nil {
			return []p11.Object{}, err
		}

		candidateCertificates = append(candidateCertificates, searchSubjectResults...)
	}

	if searchIssuer != nil || searchSerial != nil {
		searchIssuerSerialResults, err := s.slot.highBackend.QueryIssuerSerial(searchIssuer, searchSerial)
		if err != nil {
			return []p11.Object{}, err
		}

		candidateCertificates = append(candidateCertificates, searchIssuerSerialResults...)
	}

	candidateObjects := []p11.Object{}

	if includeBuiltin {
		candidateObjects = append(candidateObjects, &builtinObject{})
	}

	for _, cert := range candidateCertificates {
		candidateObjects = append(candidateObjects, &certificateObject{
			data: cert,
			includeBuiltinPolicy: includeBuiltin,
		})

		if isTrusted {
			candidateObjects = append(candidateObjects, &trustObject{
				data: cert,
			})
		}
	}

	result := []p11.Object{}

	for _, obj := range candidateObjects {
		if checkObjectTemplate(obj, template) {
			result = append(result, obj)
		}
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

func (s *session) SetPIN(old, new string) error {
	return pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

func checkObjectTemplate(obj p11.Object, template []*pkcs11.Attribute) bool {
	for _, tempAttr := range template {
		objData, err := obj.Attribute(tempAttr.Type)
		if err != nil {
			return false
		}

		tempData := tempAttr.Value

		if ! bytes.Equal(objData, tempData) {
			return false
		}
	}

	return true
}

func marshalAttributeValue(x interface{}) []byte {
	a := pkcs11.NewAttribute(1, x)
	return a.Value
}

func (obj *builtinObject) Attribute(attributeType uint) ([]byte, error) {
	switch attributeType {
		case pkcs11.CKA_CLASS:
			return marshalAttributeValue(pkcs11.CKO_NSS_BUILTIN_ROOT_LIST), nil
		case pkcs11.CKA_TOKEN:
			return marshalAttributeValue(true), nil
		case pkcs11.CKA_PRIVATE:
			return marshalAttributeValue(false), nil
		case pkcs11.CKA_MODIFIABLE:
			return marshalAttributeValue(false), nil
		case pkcs11.CKA_LABEL:
			return marshalAttributeValue("Mozilla Builtin Roots"), nil
		default:
			return nil, nil
	}
}

func (obj *builtinObject) Copy(template []*pkcs11.Attribute) (p11.Object, error) {
	return nil, pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

// TODO: Patch p11 to avoid marshalAttributeValue here
func (obj *certificateObject) Attribute(attributeType uint) ([]byte, error) {
	switch attributeType {
		case pkcs11.CKA_CLASS:
			return marshalAttributeValue(pkcs11.CKO_CERTIFICATE), nil
		case pkcs11.CKA_TOKEN:
			return marshalAttributeValue(true), nil
		case pkcs11.CKA_PRIVATE:
			return marshalAttributeValue(false), nil
		case pkcs11.CKA_MODIFIABLE:
			return marshalAttributeValue(false), nil
		case pkcs11.CKA_LABEL:
			return marshalAttributeValue(obj.data.Label), nil
		case pkcs11.CKA_CERTIFICATE_TYPE:
			return marshalAttributeValue(pkcs11.CKC_X_509), nil
		case pkcs11.CKA_SUBJECT:
			return marshalAttributeValue(obj.data.Certificate.RawSubject), nil
		case pkcs11.CKA_ID:
			return marshalAttributeValue("0"), nil
		case pkcs11.CKA_ISSUER:
			return marshalAttributeValue(obj.data.Certificate.RawIssuer), nil
		case pkcs11.CKA_SERIAL_NUMBER:
			asn1SerialNumber, err := asn1.Marshal(obj.data.Certificate.SerialNumber)
			if err != nil {
				log.Printf("Error marshaling SerialNumber\n")
				return nil, nil
			}

			return marshalAttributeValue(asn1SerialNumber), nil
		case pkcs11.CKA_VALUE:
			return marshalAttributeValue(obj.data.Certificate.Raw), nil
		case pkcs11.CKA_NSS_MOZILLA_CA_POLICY:
			if obj.includeBuiltinPolicy {
				return marshalAttributeValue(obj.data.BuiltinPolicy), nil
			} else {
				return nil, nil
			}
		default:
			return nil, nil
	}
}

func (obj *certificateObject) Copy(template []*pkcs11.Attribute) (p11.Object, error) {
	return nil, pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}

func (obj *trustObject) Attribute(attributeType uint) ([]byte, error) {
	switch attributeType {
		case pkcs11.CKA_CLASS:
			return marshalAttributeValue(pkcs11.CKO_NSS_TRUST), nil
		case pkcs11.CKA_TOKEN:
			return marshalAttributeValue(true), nil
		case pkcs11.CKA_PRIVATE:
			return marshalAttributeValue(false), nil
		case pkcs11.CKA_MODIFIABLE:
			return marshalAttributeValue(false), nil
		case pkcs11.CKA_LABEL:
			return marshalAttributeValue(obj.data.Label), nil
		case pkcs11.CKA_CERT_SHA1_HASH:
			// Yes, NSS is a pile of fail and uses SHA1 to identify
			// certificates.  They should probably fix this in the
			// future.
			sha1Array := sha1.Sum(obj.data.Certificate.Raw)

			return marshalAttributeValue(sha1Array[:]), nil
		case pkcs11.CKA_ISSUER:
			return marshalAttributeValue(obj.data.Certificate.RawIssuer), nil
		case pkcs11.CKA_SERIAL_NUMBER:
			asn1SerialNumber, err := asn1.Marshal(obj.data.Certificate.SerialNumber)
			if err != nil {
				log.Printf("Error marshaling SerialNumber\n")
				return nil, nil
			}

			return marshalAttributeValue(asn1SerialNumber), nil
		case pkcs11.CKA_TRUST_SERVER_AUTH:
			if obj.data.TrustServerAuth == 0 {
				return marshalAttributeValue(pkcs11.CKT_NSS_TRUST_UNKNOWN), nil
			}

			return marshalAttributeValue(obj.data.TrustServerAuth), nil
		case pkcs11.CKA_TRUST_CLIENT_AUTH:
			if obj.data.TrustClientAuth == 0 {
				return marshalAttributeValue(pkcs11.CKT_NSS_TRUST_UNKNOWN), nil
			}

			return marshalAttributeValue(obj.data.TrustClientAuth)
		case pkcs11.CKA_TRUST_CODE_SIGNING:
			if obj.data.TrustCodeSigning == 0 {
				return marshalAttributeValue(pkcs11.CKT_NSS_TRUST_UNKNOWN), nil
			}

			return marshalAttributeValue(obj.data.TrustCodeSigning), nil
		case pkcs11.CKA_TRUST_EMAIL_PROTECTION:
			if obj.data.TrustEmailProtection == 0 {
				return marshalAttributeValue(pkcs11.CKT_NSS_TRUST_UNKNOWN), nil
			}

			return marshalAttributeValue(obj.data.TrustEmailProtection), nil
		case pkcs11.CKA_TRUST_STEP_UP_APPROVED:
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
			return marshalAttributeValue(false), nil
		default:
			return nil, nil
	}
}

func (obj *trustObject) Copy(template []*pkcs11.Attribute) (p11.Object, error) {
	return nil, pkcs11.Error(pkcs11.CKR_TOKEN_WRITE_PROTECTED)
}
