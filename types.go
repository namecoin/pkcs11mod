// Copyright 2018 Namecoin Developers LGPLv3+

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

*/
import "C"

import (
	"fmt"
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
	return C.CK_RV(e.(pkcs11.Error))
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
			//C.free(buf) // Removed compared to miekg implementation since it's not desired here
		}
		l2[i] = x
	}
	return l2
}

// fromTemplate converts from a []*pkcs11.Attribute to a C style array that
// already contains a template as is passed to C_GetAttributeValue.
func fromTemplate(template []*pkcs11.Attribute, clist C.CK_ATTRIBUTE_PTR) error {
	l1 := make([]C.CK_ATTRIBUTE_PTR, int(len(template)))
	for i := 0; i < len(l1); i++ {
		l1[i] = C.IndexAttributePtr(clist, C.CK_ULONG(i))
	}
	bufferTooSmall := false
	for i, x := range template {
		c := l1[i]
		cLen := C.CK_ULONG(uint(len(x.Value)))
		if C.getAttributePval(c) == nil {
			c.ulValueLen = cLen
		} else if c.ulValueLen >= cLen {
			buf := unsafe.Pointer(C.getAttributePval(c))

			// Adapted from solution 3 of https://stackoverflow.com/a/35675259
			goBuf := (*[1 << 30]byte)(buf)
			copy(goBuf[:], x.Value)

			c.ulValueLen = cLen
		} else {
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
		return false, fmt.Errorf("Invalid length: %d", len(arg))
	}

	return fromCBBool(*(*C.CK_BBOOL)(unsafe.Pointer(&arg[0]))), nil
}

func BytesToULong(arg []byte) (uint, error) {
	// TODO: use cgo to get the actual size of ULong instead of guessing "at least 4"
	if len(arg) < 4 {
		return 0, fmt.Errorf("Invalid length: %d", len(arg))
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
		pssParam := C.CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism.pParameter)
		goHashAlg := uint(pssParam.hashAlg)
		goMgf := uint(pssParam.mgf)
		goSLen := uint(pssParam.sLen)
		return pkcs11.NewMechanism(uint(pMechanism.mechanism), pkcs11.NewPSSParams(goHashAlg, goMgf, goSLen))
	case C.CKM_AES_GCM:
		gcmParam := C.CK_GCM_PARAMS_PTR(pMechanism.pParameter)
		goIV := C.GoBytes(unsafe.Pointer(gcmParam.pIv), C.int(gcmParam.ulIvLen))
		goAad := C.GoBytes(unsafe.Pointer(gcmParam.pAAD), C.int(gcmParam.ulAADLen))
		goTag := int(gcmParam.ulTagBits)
		return pkcs11.NewMechanism(uint(pMechanism.mechanism), pkcs11.NewGCMParams(goIV, goAad, goTag))
	case C.CKM_RSA_PKCS_OAEP:
		oaepParams := C.CK_RSA_PKCS_OAEP_PARAMS_PTR(pMechanism.pParameter)
		goHashAlg := uint(oaepParams.hashAlg)
		goMgf := uint(oaepParams.mgf)
		goSourceType := uint(oaepParams.source)
		goSourceData := C.GoBytes(unsafe.Pointer(oaepParams.pSourceData), C.int(oaepParams.ulSourceDataLen))
		return pkcs11.NewMechanism(uint(pMechanism.mechanism), pkcs11.NewOAEPParams(goHashAlg, goMgf, goSourceType, goSourceData))
	default:
		return pkcs11.NewMechanism(uint(pMechanism.mechanism), nil)
	}
	return nil
}
