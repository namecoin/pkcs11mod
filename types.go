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

/*
#include "spec/pkcs11go.h"

void SetIndex(CK_ULONG_PTR array, CK_ULONG i, CK_ULONG val)
{
	array[i] = val;
}

CK_ATTRIBUTE_PTR IndexAttributePtr(CK_ATTRIBUTE_PTR array, CK_ULONG i)
{
	return &(array[i]);
}

// Copied verbatim from miekg/pkcs11 pkcs11.go
static inline CK_VOID_PTR getAttributePval(CK_ATTRIBUTE_PTR a)
{
	return a->pValue;
}

static inline CK_VOID_PTR getMechanismParam(CK_MECHANISM_PTR m)
{
	return m->pParameter;
}

static inline CK_VOID_PTR getOAEPSourceData(CK_RSA_PKCS_OAEP_PARAMS_PTR params)
{
	return params->pSourceData;
}

*/
import "C"

import (
	"fmt"
	"log"
	"unsafe"

	"github.com/miekg/pkcs11"
)

// fromList converts from a []uint to a C style array.
func fromList(goList []uint, cList C.CK_ULONG_PTR, goSize uint) {
	for i := 0; uint(i) < goSize; i++ {
		C.SetIndex(cList, C.CK_ULONG(i), C.CK_ULONG(goList[i]))
	}
}

// fromMechanismList converts from a []*pkcs11.Mechanism to a C style array of
// mechanism types.
func fromMechanismList(goList []*pkcs11.Mechanism, cList C.CK_ULONG_PTR, goSize uint) {
	for i := 0; uint(i) < goSize; i++ {
		C.SetIndex(cList, C.CK_ULONG(i), C.CK_ULONG(goList[i].Mechanism))
	}
}

// fromObjectHandleList converts from a []pkcs11.ObjectHandle to a C style array.
func fromObjectHandleList(goList []pkcs11.ObjectHandle, cList C.CK_ULONG_PTR, goSize uint) {
	for i := 0; uint(i) < goSize; i++ {
		C.SetIndex(cList, C.CK_ULONG(i), C.CK_ULONG(goList[i]))
	}
}

// fromCBBool converts a CK_BBOOL to a bool.
func fromCBBool(x C.CK_BBOOL) bool {
	// Any nonzero value means true, and zero means false.
	return x != C.CK_FALSE
}

func fromError(e error) C.CK_RV {
	if e == nil {
		return C.CKR_OK
	}

	pe, ok := e.(pkcs11.Error)
	if !ok {
		// This error doesn't map to a PKCS#11 error code.  Return a generic
		// "function failed" error instead.
		pe = pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
	}

	return C.CK_RV(pe)
}

// toTemplate converts from a C style array to a []*pkcs11.Attribute.
// It doesn't free the input array.
func toTemplate(clist C.CK_ATTRIBUTE_PTR, size C.CK_ULONG) []*pkcs11.Attribute {
	l1 := make([]C.CK_ATTRIBUTE_PTR, int(size))
	for i := 0; i < len(l1); i++ {
		l1[i] = C.IndexAttributePtr(clist, C.CK_ULONG(i))
	}
	// defer C.free(unsafe.Pointer(clist)) // Removed compared to miekg implementation since it's not desired here
	l2 := make([]*pkcs11.Attribute, int(size))
	for i, c := range l1 {
		x := new(pkcs11.Attribute)
		x.Type = uint(c._type)
		if int(c.ulValueLen) != -1 {
			buf := unsafe.Pointer(C.getAttributePval(c))
			x.Value = C.GoBytes(buf, C.int(c.ulValueLen))
			// C.free(buf) // Removed compared to miekg implementation since it's not desired here
		}
		l2[i] = x
	}
	return l2
}

// fromTemplate converts from a []*pkcs11.Attribute to a C style array that
// already contains a template as is passed to C_GetAttributeValue.
func fromTemplate(template []*pkcs11.Attribute, clist C.CK_ATTRIBUTE_PTR) error {
	l1 := make([]C.CK_ATTRIBUTE_PTR, len(template))
	for i := 0; i < len(l1); i++ {
		l1[i] = C.IndexAttributePtr(clist, C.CK_ULONG(i))
	}
	bufferTooSmall := false
	for i, x := range template {
		if trace {
			log.Printf("pkcs11mod fromTemplate: %s", AttrTrace(x))
		}

		c := l1[i]
		if x.Value == nil {
			// CKR_ATTRIBUTE_TYPE_INVALID or CKR_ATTRIBUTE_SENSITIVE
			c.ulValueLen = C.CK_UNAVAILABLE_INFORMATION
			continue
		}
		cLen := C.CK_ULONG(uint(len(x.Value)))
		switch {
		case C.getAttributePval(c) == nil:
			c.ulValueLen = cLen
		case c.ulValueLen >= cLen:
			buf := unsafe.Pointer(C.getAttributePval(c))

			// Adapted from solution 3 of https://stackoverflow.com/a/35675259
			goBuf := (*[1 << 30]byte)(buf)
			copy(goBuf[:], x.Value)

			c.ulValueLen = cLen
		default:
			c.ulValueLen = C.CK_UNAVAILABLE_INFORMATION
			bufferTooSmall = true
		}
	}

	if bufferTooSmall {
		return pkcs11.Error(pkcs11.CKR_BUFFER_TOO_SMALL)
	}

	return nil
}

func BytesToBool(arg []byte) (bool, error) {
	if len(arg) != 1 {
		return false, fmt.Errorf("invalid length: %d", len(arg))
	}

	return fromCBBool(*(*C.CK_BBOOL)(unsafe.Pointer(&arg[0]))), nil
}

func BytesToULong(arg []byte) (uint, error) {
	// TODO: use cgo to get the actual size of ULong instead of guessing "at least 4"
	if len(arg) < 4 {
		return 0, fmt.Errorf("invalid length: %d", len(arg))
	}

	return uint(*(*C.CK_ULONG)(unsafe.Pointer(&arg[0]))), nil
}

// toMechanism converts from a C pointer to a *pkcs11.Mechanism.
// It doesn't free the input object.
func toMechanism(pMechanism C.CK_MECHANISM_PTR) *pkcs11.Mechanism {
	switch pMechanism.mechanism {
	case C.CKM_RSA_PKCS_PSS, C.CKM_SHA1_RSA_PKCS_PSS,
		C.CKM_SHA224_RSA_PKCS_PSS, C.CKM_SHA256_RSA_PKCS_PSS,
		C.CKM_SHA384_RSA_PKCS_PSS, C.CKM_SHA512_RSA_PKCS_PSS,
		C.CKM_SHA3_256_RSA_PKCS_PSS, C.CKM_SHA3_384_RSA_PKCS_PSS,
		C.CKM_SHA3_512_RSA_PKCS_PSS, C.CKM_SHA3_224_RSA_PKCS_PSS:
		pssParam := C.CK_RSA_PKCS_PSS_PARAMS_PTR(C.getMechanismParam(pMechanism))
		goHashAlg := uint(pssParam.hashAlg)
		goMgf := uint(pssParam.mgf)
		goSLen := uint(pssParam.sLen)
		return pkcs11.NewMechanism(uint(pMechanism.mechanism), pkcs11.NewPSSParams(goHashAlg, goMgf, goSLen))
	case C.CKM_AES_GCM:
		gcmParam := C.CK_GCM_PARAMS_PTR(C.getMechanismParam(pMechanism))
		goIV := C.GoBytes(unsafe.Pointer(gcmParam.pIv), C.int(gcmParam.ulIvLen))
		goAad := C.GoBytes(unsafe.Pointer(gcmParam.pAAD), C.int(gcmParam.ulAADLen))
		goTag := int(gcmParam.ulTagBits)
		return pkcs11.NewMechanism(uint(pMechanism.mechanism), pkcs11.NewGCMParams(goIV, goAad, goTag))
	case C.CKM_RSA_PKCS_OAEP:
		oaepParams := C.CK_RSA_PKCS_OAEP_PARAMS_PTR(C.getMechanismParam(pMechanism))
		goHashAlg := uint(oaepParams.hashAlg)
		goMgf := uint(oaepParams.mgf)
		goSourceType := uint(oaepParams.source)
		goSourceData := C.GoBytes(unsafe.Pointer(C.getOAEPSourceData(oaepParams)), C.int(oaepParams.ulSourceDataLen))
		return pkcs11.NewMechanism(uint(pMechanism.mechanism), pkcs11.NewOAEPParams(goHashAlg, goMgf, goSourceType, goSourceData))
	default:
		return pkcs11.NewMechanism(uint(pMechanism.mechanism), nil)
	}
}

var strCKA = map[uint]string{
	// awk '/#define CKA_/{ print "pkcs11."$2":\""$2"\"," }' pkcs11t.h | grep -v CKA_SUB_PRIME_BITS | grep -v CKA_EC_PARAMS
	pkcs11.CKA_CLASS:"CKA_CLASS",
	pkcs11.CKA_TOKEN:"CKA_TOKEN",
	pkcs11.CKA_PRIVATE:"CKA_PRIVATE",
	pkcs11.CKA_LABEL:"CKA_LABEL",
	pkcs11.CKA_APPLICATION:"CKA_APPLICATION",
	pkcs11.CKA_VALUE:"CKA_VALUE",
	pkcs11.CKA_OBJECT_ID:"CKA_OBJECT_ID",
	pkcs11.CKA_CERTIFICATE_TYPE:"CKA_CERTIFICATE_TYPE",
	pkcs11.CKA_ISSUER:"CKA_ISSUER",
	pkcs11.CKA_SERIAL_NUMBER:"CKA_SERIAL_NUMBER",
	pkcs11.CKA_AC_ISSUER:"CKA_AC_ISSUER",
	pkcs11.CKA_OWNER:"CKA_OWNER",
	pkcs11.CKA_ATTR_TYPES:"CKA_ATTR_TYPES",
	pkcs11.CKA_TRUSTED:"CKA_TRUSTED",
	pkcs11.CKA_CERTIFICATE_CATEGORY:"CKA_CERTIFICATE_CATEGORY",
	pkcs11.CKA_JAVA_MIDP_SECURITY_DOMAIN:"CKA_JAVA_MIDP_SECURITY_DOMAIN",
	pkcs11.CKA_URL:"CKA_URL",
	pkcs11.CKA_HASH_OF_SUBJECT_PUBLIC_KEY:"CKA_HASH_OF_SUBJECT_PUBLIC_KEY",
	pkcs11.CKA_HASH_OF_ISSUER_PUBLIC_KEY:"CKA_HASH_OF_ISSUER_PUBLIC_KEY",
	pkcs11.CKA_NAME_HASH_ALGORITHM:"CKA_NAME_HASH_ALGORITHM",
	pkcs11.CKA_CHECK_VALUE:"CKA_CHECK_VALUE",
	pkcs11.CKA_KEY_TYPE:"CKA_KEY_TYPE",
	pkcs11.CKA_SUBJECT:"CKA_SUBJECT",
	pkcs11.CKA_ID:"CKA_ID",
	pkcs11.CKA_SENSITIVE:"CKA_SENSITIVE",
	pkcs11.CKA_ENCRYPT:"CKA_ENCRYPT",
	pkcs11.CKA_DECRYPT:"CKA_DECRYPT",
	pkcs11.CKA_WRAP:"CKA_WRAP",
	pkcs11.CKA_UNWRAP:"CKA_UNWRAP",
	pkcs11.CKA_SIGN:"CKA_SIGN",
	pkcs11.CKA_SIGN_RECOVER:"CKA_SIGN_RECOVER",
	pkcs11.CKA_VERIFY:"CKA_VERIFY",
	pkcs11.CKA_VERIFY_RECOVER:"CKA_VERIFY_RECOVER",
	pkcs11.CKA_DERIVE:"CKA_DERIVE",
	pkcs11.CKA_START_DATE:"CKA_START_DATE",
	pkcs11.CKA_END_DATE:"CKA_END_DATE",
	pkcs11.CKA_MODULUS:"CKA_MODULUS",
	pkcs11.CKA_MODULUS_BITS:"CKA_MODULUS_BITS",
	pkcs11.CKA_PUBLIC_EXPONENT:"CKA_PUBLIC_EXPONENT",
	pkcs11.CKA_PRIVATE_EXPONENT:"CKA_PRIVATE_EXPONENT",
	pkcs11.CKA_PRIME_1:"CKA_PRIME_1",
	pkcs11.CKA_PRIME_2:"CKA_PRIME_2",
	pkcs11.CKA_EXPONENT_1:"CKA_EXPONENT_1",
	pkcs11.CKA_EXPONENT_2:"CKA_EXPONENT_2",
	pkcs11.CKA_COEFFICIENT:"CKA_COEFFICIENT",
	pkcs11.CKA_PUBLIC_KEY_INFO:"CKA_PUBLIC_KEY_INFO",
	pkcs11.CKA_PRIME:"CKA_PRIME",
	pkcs11.CKA_SUBPRIME:"CKA_SUBPRIME",
	pkcs11.CKA_BASE:"CKA_BASE",
	pkcs11.CKA_PRIME_BITS:"CKA_PRIME_BITS",
	pkcs11.CKA_SUBPRIME_BITS:"CKA_SUBPRIME_BITS",
	pkcs11.CKA_VALUE_BITS:"CKA_VALUE_BITS",
	pkcs11.CKA_VALUE_LEN:"CKA_VALUE_LEN",
	pkcs11.CKA_EXTRACTABLE:"CKA_EXTRACTABLE",
	pkcs11.CKA_LOCAL:"CKA_LOCAL",
	pkcs11.CKA_NEVER_EXTRACTABLE:"CKA_NEVER_EXTRACTABLE",
	pkcs11.CKA_ALWAYS_SENSITIVE:"CKA_ALWAYS_SENSITIVE",
	pkcs11.CKA_KEY_GEN_MECHANISM:"CKA_KEY_GEN_MECHANISM",
	pkcs11.CKA_MODIFIABLE:"CKA_MODIFIABLE",
	pkcs11.CKA_COPYABLE:"CKA_COPYABLE",
	pkcs11.CKA_DESTROYABLE:"CKA_DESTROYABLE",
	pkcs11.CKA_ECDSA_PARAMS:"CKA_ECDSA_PARAMS",
	pkcs11.CKA_EC_POINT:"CKA_EC_POINT",
	pkcs11.CKA_SECONDARY_AUTH:"CKA_SECONDARY_AUTH",
	pkcs11.CKA_AUTH_PIN_FLAGS:"CKA_AUTH_PIN_FLAGS",
	pkcs11.CKA_ALWAYS_AUTHENTICATE:"CKA_ALWAYS_AUTHENTICATE",
	pkcs11.CKA_WRAP_WITH_TRUSTED:"CKA_WRAP_WITH_TRUSTED",
	pkcs11.CKA_WRAP_TEMPLATE:"CKA_WRAP_TEMPLATE",
	pkcs11.CKA_UNWRAP_TEMPLATE:"CKA_UNWRAP_TEMPLATE",
	pkcs11.CKA_DERIVE_TEMPLATE:"CKA_DERIVE_TEMPLATE",
	pkcs11.CKA_OTP_FORMAT:"CKA_OTP_FORMAT",
	pkcs11.CKA_OTP_LENGTH:"CKA_OTP_LENGTH",
	pkcs11.CKA_OTP_TIME_INTERVAL:"CKA_OTP_TIME_INTERVAL",
	pkcs11.CKA_OTP_USER_FRIENDLY_MODE:"CKA_OTP_USER_FRIENDLY_MODE",
	pkcs11.CKA_OTP_CHALLENGE_REQUIREMENT:"CKA_OTP_CHALLENGE_REQUIREMENT",
	pkcs11.CKA_OTP_TIME_REQUIREMENT:"CKA_OTP_TIME_REQUIREMENT",
	pkcs11.CKA_OTP_COUNTER_REQUIREMENT:"CKA_OTP_COUNTER_REQUIREMENT",
	pkcs11.CKA_OTP_PIN_REQUIREMENT:"CKA_OTP_PIN_REQUIREMENT",
	pkcs11.CKA_OTP_COUNTER:"CKA_OTP_COUNTER",
	pkcs11.CKA_OTP_TIME:"CKA_OTP_TIME",
	pkcs11.CKA_OTP_USER_IDENTIFIER:"CKA_OTP_USER_IDENTIFIER",
	pkcs11.CKA_OTP_SERVICE_IDENTIFIER:"CKA_OTP_SERVICE_IDENTIFIER",
	pkcs11.CKA_OTP_SERVICE_LOGO:"CKA_OTP_SERVICE_LOGO",
	pkcs11.CKA_OTP_SERVICE_LOGO_TYPE:"CKA_OTP_SERVICE_LOGO_TYPE",
	pkcs11.CKA_GOSTR3410_PARAMS:"CKA_GOSTR3410_PARAMS",
	pkcs11.CKA_GOSTR3411_PARAMS:"CKA_GOSTR3411_PARAMS",
	pkcs11.CKA_GOST28147_PARAMS:"CKA_GOST28147_PARAMS",
	pkcs11.CKA_HW_FEATURE_TYPE:"CKA_HW_FEATURE_TYPE",
	pkcs11.CKA_RESET_ON_INIT:"CKA_RESET_ON_INIT",
	pkcs11.CKA_HAS_RESET:"CKA_HAS_RESET",
	pkcs11.CKA_PIXEL_X:"CKA_PIXEL_X",
	pkcs11.CKA_PIXEL_Y:"CKA_PIXEL_Y",
	pkcs11.CKA_RESOLUTION:"CKA_RESOLUTION",
	pkcs11.CKA_CHAR_ROWS:"CKA_CHAR_ROWS",
	pkcs11.CKA_CHAR_COLUMNS:"CKA_CHAR_COLUMNS",
	pkcs11.CKA_COLOR:"CKA_COLOR",
	pkcs11.CKA_BITS_PER_PIXEL:"CKA_BITS_PER_PIXEL",
	pkcs11.CKA_CHAR_SETS:"CKA_CHAR_SETS",
	pkcs11.CKA_ENCODING_METHODS:"CKA_ENCODING_METHODS",
	pkcs11.CKA_MIME_TYPES:"CKA_MIME_TYPES",
	pkcs11.CKA_MECHANISM_TYPE:"CKA_MECHANISM_TYPE",
	pkcs11.CKA_REQUIRED_CMS_ATTRIBUTES:"CKA_REQUIRED_CMS_ATTRIBUTES",
	pkcs11.CKA_DEFAULT_CMS_ATTRIBUTES:"CKA_DEFAULT_CMS_ATTRIBUTES",
	pkcs11.CKA_SUPPORTED_CMS_ATTRIBUTES:"CKA_SUPPORTED_CMS_ATTRIBUTES",
	pkcs11.CKA_ALLOWED_MECHANISMS:"CKA_ALLOWED_MECHANISMS",
	pkcs11.CKA_VENDOR_DEFINED:"CKA_VENDOR_DEFINED",

	// awk '/CKA_/{ print "pkcs11."$1":\""$1"\"," }' vendor.go
	pkcs11.CKA_NCIPHER:"CKA_NCIPHER",
	pkcs11.CKA_NSS:"CKA_NSS",
	pkcs11.CKA_TRUST:"CKA_TRUST",
	pkcs11.CKA_NSS_URL:"CKA_NSS_URL",
	pkcs11.CKA_NSS_EMAIL:"CKA_NSS_EMAIL",
	pkcs11.CKA_NSS_SMIME_INFO:"CKA_NSS_SMIME_INFO",
	pkcs11.CKA_NSS_SMIME_TIMESTAMP:"CKA_NSS_SMIME_TIMESTAMP",
	pkcs11.CKA_NSS_PKCS8_SALT:"CKA_NSS_PKCS8_SALT",
	pkcs11.CKA_NSS_PASSWORD_CHECK:"CKA_NSS_PASSWORD_CHECK",
	pkcs11.CKA_NSS_EXPIRES:"CKA_NSS_EXPIRES",
	pkcs11.CKA_NSS_KRL:"CKA_NSS_KRL",
	pkcs11.CKA_NSS_PQG_COUNTER:"CKA_NSS_PQG_COUNTER",
	pkcs11.CKA_NSS_PQG_SEED:"CKA_NSS_PQG_SEED",
	pkcs11.CKA_NSS_PQG_H:"CKA_NSS_PQG_H",
	pkcs11.CKA_NSS_PQG_SEED_BITS:"CKA_NSS_PQG_SEED_BITS",
	pkcs11.CKA_NSS_MODULE_SPEC:"CKA_NSS_MODULE_SPEC",
	pkcs11.CKA_NSS_OVERRIDE_EXTENSIONS:"CKA_NSS_OVERRIDE_EXTENSIONS",
	pkcs11.CKA_NSS_JPAKE_SIGNERID:"CKA_NSS_JPAKE_SIGNERID",
	pkcs11.CKA_NSS_JPAKE_PEERID:"CKA_NSS_JPAKE_PEERID",
	pkcs11.CKA_NSS_JPAKE_GX1:"CKA_NSS_JPAKE_GX1",
	pkcs11.CKA_NSS_JPAKE_GX2:"CKA_NSS_JPAKE_GX2",
	pkcs11.CKA_NSS_JPAKE_GX3:"CKA_NSS_JPAKE_GX3",
	pkcs11.CKA_NSS_JPAKE_GX4:"CKA_NSS_JPAKE_GX4",
	pkcs11.CKA_NSS_JPAKE_X2:"CKA_NSS_JPAKE_X2",
	pkcs11.CKA_NSS_JPAKE_X2S:"CKA_NSS_JPAKE_X2S",
	pkcs11.CKA_NSS_MOZILLA_CA_POLICY:"CKA_NSS_MOZILLA_CA_POLICY",
	pkcs11.CKA_TRUST_DIGITAL_SIGNATURE:"CKA_TRUST_DIGITAL_SIGNATURE",
	pkcs11.CKA_TRUST_NON_REPUDIATION:"CKA_TRUST_NON_REPUDIATION",
	pkcs11.CKA_TRUST_KEY_ENCIPHERMENT:"CKA_TRUST_KEY_ENCIPHERMENT",
	pkcs11.CKA_TRUST_DATA_ENCIPHERMENT:"CKA_TRUST_DATA_ENCIPHERMENT",
	pkcs11.CKA_TRUST_KEY_AGREEMENT:"CKA_TRUST_KEY_AGREEMENT",
	pkcs11.CKA_TRUST_KEY_CERT_SIGN:"CKA_TRUST_KEY_CERT_SIGN",
	pkcs11.CKA_TRUST_CRL_SIGN:"CKA_TRUST_CRL_SIGN",
	pkcs11.CKA_TRUST_SERVER_AUTH:"CKA_TRUST_SERVER_AUTH",
	pkcs11.CKA_TRUST_CLIENT_AUTH:"CKA_TRUST_CLIENT_AUTH",
	pkcs11.CKA_TRUST_CODE_SIGNING:"CKA_TRUST_CODE_SIGNING",
	pkcs11.CKA_TRUST_EMAIL_PROTECTION:"CKA_TRUST_EMAIL_PROTECTION",
	pkcs11.CKA_TRUST_IPSEC_END_SYSTEM:"CKA_TRUST_IPSEC_END_SYSTEM",
	pkcs11.CKA_TRUST_IPSEC_TUNNEL:"CKA_TRUST_IPSEC_TUNNEL",
	pkcs11.CKA_TRUST_IPSEC_USER:"CKA_TRUST_IPSEC_USER",
	pkcs11.CKA_TRUST_TIME_STAMPING:"CKA_TRUST_TIME_STAMPING",
	pkcs11.CKA_TRUST_STEP_UP_APPROVED:"CKA_TRUST_STEP_UP_APPROVED",
	pkcs11.CKA_CERT_SHA1_HASH:"CKA_CERT_SHA1_HASH",
	pkcs11.CKA_CERT_MD5_HASH:"CKA_CERT_MD5_HASH",
}

func AttrTrace(a *pkcs11.Attribute) string {
	t, ok := strCKA[a.Type]
	if !ok {
		t = fmt.Sprintf("%d", a.Type)
	}

	if traceSensitive {
		return fmt.Sprintf("%s: %v", t, a.Value)
	} else {
		return fmt.Sprintf("%s", t)
	}
}
