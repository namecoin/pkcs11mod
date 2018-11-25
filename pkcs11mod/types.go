// Copyright 2018 Namecoin Developers LGPLv3+

package pkcs11mod

/*
#include "spec/pkcs11go.h"

void SetIndex(CK_ULONG_PTR array, CK_ULONG i, CK_ULONG val)
{
	array[i] = val;
}
*/
import "C"

import (
	"github.com/miekg/pkcs11"
)

// fromList converts from a []uint to a C style array.
func fromList(goList []uint, cList C.CK_ULONG_PTR, goSize uint) {
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
