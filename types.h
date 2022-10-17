#ifndef TYPES_H_
#define TYPES_H_

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

#endif
