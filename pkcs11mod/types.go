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
	"unsafe"

	"github.com/miekg/pkcs11"
)

// fromList converts from a []uint to a C style array.
func fromList(goList []uint, cList C.CK_ULONG_PTR, goSize uint) {
	for i := 0; uint(i) < goSize; i++ {
		C.SetIndex(cList, C.CK_ULONG(i), C.CK_ULONG(goList[i]))
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
