// Copyright 2018 Namecoin Developers GPLv3+

package main

/*
#include "spec/pkcs11go.h"
*/
import "C"

import (
	"github.com/miekg/pkcs11"
)

func fromError(e error) C.CK_RV {
	if e == nil {
		return C.CKR_OK
	}
	return C.CK_RV(e.(pkcs11.Error))
}
