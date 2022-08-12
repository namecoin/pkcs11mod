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
