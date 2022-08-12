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

// Based on https://github.com/Pkcs11Interop/pkcs11-mock/blob/d9adaaf39e0f41283cfa373597ed4b457ae28c39/src/pkcs11-mock.c

#include <string.h>

#include "spec/pkcs11go.h"

CK_RV goInitialize(void);
CK_RV goFinalize(void);
CK_RV goGetInfo(ckInfoPtr);
CK_RV goGetSlotList(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);
CK_RV goGetSlotInfo(CK_SLOT_ID, CK_SLOT_INFO_PTR);
CK_RV goGetTokenInfo(CK_SLOT_ID, CK_TOKEN_INFO_PTR);
CK_RV goGetMechanismList(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR);
CK_RV goGetMechanismInfo(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR);
CK_RV goInitPIN(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG);
CK_RV goSetPIN(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG);
CK_RV goOpenSession(CK_SLOT_ID, CK_FLAGS, CK_SESSION_HANDLE_PTR);
CK_RV goCloseSession(CK_SESSION_HANDLE);
CK_RV goCloseAllSessions(CK_SLOT_ID);
CK_RV goGetSessionInfo(CK_SESSION_HANDLE,CK_SESSION_INFO_PTR);
CK_RV goGetOperationState(CK_SESSION_HANDLE , CK_BYTE_PTR , CK_ULONG_PTR);
CK_RV goSetOperationState(CK_SESSION_HANDLE, CK_BYTE_PTR , CK_ULONG , CK_OBJECT_HANDLE , CK_OBJECT_HANDLE );
CK_RV goLogin(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG);
CK_RV goLogout(CK_SESSION_HANDLE);
CK_RV goCreateObject(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR , CK_ULONG , CK_OBJECT_HANDLE_PTR );
CK_RV goCopyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE ,CK_ATTRIBUTE_PTR , CK_ULONG ,CK_OBJECT_HANDLE_PTR );
CK_RV goDestroyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE );
CK_RV goGetObjectSize(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR);
CK_RV goGetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
CK_RV goSetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
CK_RV goFindObjectsInit(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
CK_RV goFindObjects(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR);
CK_RV goFindObjectsFinal(CK_SESSION_HANDLE);
CK_RV goEncryptInit(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE);
CK_RV goEncrypt(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goEncryptUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goEncryptFinal(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goDecryptInit(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE);
CK_RV goDecrypt(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goDecryptUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goDecryptFinal(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goDigestInit(CK_SESSION_HANDLE,CK_MECHANISM_PTR);
CK_RV goDigest(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goDigestUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG);
CK_RV goDigestKey(CK_SESSION_HANDLE,CK_OBJECT_HANDLE);
CK_RV goDigestFinal(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goSignInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
CK_RV goSignUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
CK_RV goSign(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV goSignFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV goSignRecoverInit(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE);
CK_RV goSignRecover(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goVerifyInit(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE);
CK_RV goVerify(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG);
CK_RV goVerifyUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG);
CK_RV goVerifyFinal(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG);
CK_RV goVerifyRecoverInit(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE);
CK_RV goVerifyRecover(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goDigestEncryptUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goDecryptDigestUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goSignEncryptUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goDecryptVerifyUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goGenerateKey(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR);
CK_RV goGenerateKeyPair(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_ATTRIBUTE_PTR,CK_ULONG,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR,CK_OBJECT_HANDLE_PTR);
CK_RV goWrapKey(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE,CK_OBJECT_HANDLE,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goUnwrapKey(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR);
CK_RV goDeriveKey(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR);
CK_RV goSeedRandom(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG);
CK_RV goGenerateRandom(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG);
CK_RV goWaitForSlotEvent(CK_FLAGS,CK_SLOT_ID_PTR,CK_VOID_PTR);
void goLog(const char*);

CK_FUNCTION_LIST pkcs11_functions = 
{
	{2, 20},
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent
};

// We have to match the PKCS#11 API exactly here, but many of the parameters
// aren't passed to Go (either because they're unsupported features, or they're
// reserved.)  Don't trigger compiler warrnings about this.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	return goInitialize();
}


CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	return goFinalize();
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	// Handle packing compatibility for Go.
	// Based on CK_RV GetInfo in pkcs11.go from miekg/pkcs11

	ckInfo goInfo;
	CK_RV ret = goGetInfo(&goInfo);

	pInfo->cryptokiVersion = goInfo.cryptokiVersion;
	memcpy(pInfo->manufacturerID, goInfo.manufacturerID, sizeof(pInfo->manufacturerID));
	pInfo->flags = goInfo.flags;
	memcpy(pInfo->libraryDescription, goInfo.libraryDescription, sizeof(pInfo->libraryDescription));
	pInfo->libraryVersion = goInfo.libraryVersion;

	return ret;
}


// Export in Windows DLL's (workaround for change introduced by
// https://github.com/golang/go/issues/30674 ).
#ifdef _WIN32
	__declspec(dllexport)
#endif
CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (NULL == ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &pkcs11_functions;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	return goGetSlotList(tokenPresent, pSlotList, pulCount);
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	return goGetSlotInfo(slotID, pInfo);
}


CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	return goGetTokenInfo(slotID, pInfo);
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	return goGetMechanismList(slotID, pMechanismList, pulCount);
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	return goGetMechanismInfo(slotID, type, pInfo);
}


CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	return goInitPIN(hSession, pPin, ulPinLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	return goSetPIN(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	return goOpenSession(slotID, flags, phSession);
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
	return goCloseSession(hSession);
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{	
	return goCloseAllSessions(slotID);
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	return goGetSessionInfo(hSession, pInfo);
}


CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	return goGetOperationState(hSession, pOperationState, pulOperationStateLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{

	return goSetOperationState(hSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	return goLogin(hSession, userType, pPin, ulPinLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{	
	return goLogout(hSession);
}


CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	return goCreateObject(hSession, pTemplate, ulCount, phObject);
}


CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	return goCopyObject(hSession, hObject, pTemplate, ulCount, phNewObject);
}


CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	return goDestroyObject(hSession, hObject);
}


CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	return goGetObjectSize(hSession, hObject, pulSize);
}


CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	return goGetAttributeValue(hSession, hObject, pTemplate, ulCount);
}


CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	return goSetAttributeValue(hSession, hObject, pTemplate, ulCount);
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	return goFindObjectsInit(hSession, pTemplate, ulCount);
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	return goFindObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount);
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
	return goFindObjectsFinal(hSession);
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return goEncryptInit(hSession, pMechanism, hKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	return goEncrypt(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	return goEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	return goEncryptFinal(hSession, pLastEncryptedPart, pulLastEncryptedPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return goDecryptInit(hSession, pMechanism, hKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	return goDecrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return goDecryptUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	return goDecryptFinal(hSession, pLastPart, pulLastPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	return goDigestInit(hSession, pMechanism);
}


CK_DEFINE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	return goDigest(hSession, pData, ulDataLen, pDigest, pulDigestLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return goDigestUpdate(hSession, pPart, ulPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	return goDigestKey(hSession, hKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	return goDigestFinal(hSession, pDigest, pulDigestLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return goSignInit(hSession, pMechanism, hKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	return goSign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return goSignUpdate(hSession, pPart, ulPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	return goSignFinal(hSession, pSignature, pulSignatureLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return goSignRecoverInit(hSession, pMechanism, hKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	return goSignRecover(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return goVerifyInit(hSession, pMechanism, hKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	return goVerify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return goVerifyUpdate(hSession, pPart, ulPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	return goVerifyFinal(hSession, pSignature, ulSignatureLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return goVerifyRecoverInit(hSession, pMechanism, hKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	return goVerifyRecover(hSession, pSignature, ulSignatureLen, pData, pulDataLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	return goDigestEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return goDecryptDigestUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	return goSignEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return goDecryptVerifyUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	return goGenerateKey(hSession, pMechanism, pTemplate, ulCount, phKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	return goGenerateKeyPair(hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	return goWrapKey(hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	return goUnwrapKey(hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttributeCount, phKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	return goDeriveKey(hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	return goSeedRandom(hSession, pSeed, ulSeedLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	return goGenerateRandom(hSession, RandomData, ulRandomLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	return goWaitForSlotEvent(flags, pSlot, pReserved);
}

#pragma GCC diagnostic pop
