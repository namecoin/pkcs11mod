// Based on https://github.com/Pkcs11Interop/pkcs11-mock/blob/d9adaaf39e0f41283cfa373597ed4b457ae28c39/src/pkcs11-mock.c

#include <string.h>

#include "spec/pkcs11go.h"

CK_RV Go_Initialize();
CK_RV Go_Finalize();
CK_RV Go_GetInfo(ckInfoPtr);
CK_RV Go_GetSlotList(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);
CK_RV Go_GetSlotInfo(CK_SLOT_ID, CK_SLOT_INFO_PTR);
CK_RV Go_GetTokenInfo(CK_SLOT_ID, CK_TOKEN_INFO_PTR);
CK_RV Go_GetMechanismList(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR);
CK_RV Go_GetMechanismInfo(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR);
CK_RV Go_InitPIN(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG);
CK_RV Go_SetPIN(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG);
CK_RV Go_OpenSession(CK_SLOT_ID, CK_FLAGS, CK_SESSION_HANDLE_PTR);
CK_RV Go_CloseSession(CK_SESSION_HANDLE);
CK_RV Go_CloseAllSessions(CK_SLOT_ID);
CK_RV Go_GetSessionInfo(CK_SESSION_HANDLE,CK_SESSION_INFO_PTR);
CK_RV Go_GetOperationState(CK_SESSION_HANDLE , CK_BYTE_PTR , CK_ULONG_PTR);
CK_RV Go_SetOperationState(CK_SESSION_HANDLE, CK_BYTE_PTR , CK_ULONG , CK_OBJECT_HANDLE , CK_OBJECT_HANDLE );
CK_RV Go_Login(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG);
CK_RV Go_Logout(CK_SESSION_HANDLE);
CK_RV Go_CreateObject(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR , CK_ULONG , CK_OBJECT_HANDLE_PTR );
CK_RV Go_CopyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE ,CK_ATTRIBUTE_PTR , CK_ULONG ,CK_OBJECT_HANDLE_PTR );
CK_RV Go_DestroyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE );
CK_RV Go_GetObjectSize(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR);
CK_RV Go_GetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
CK_RV Go_SetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
CK_RV Go_FindObjectsInit(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
CK_RV Go_FindObjects(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR);
CK_RV Go_FindObjectsFinal(CK_SESSION_HANDLE);
CK_RV Go_EncryptInit(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE);
CK_RV Go_Encrypt(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV Go_EncryptUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV Go_EncryptFinal(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV Go_DecryptInit(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE);
CK_RV Go_Decrypt(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV Go_DecryptUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV Go_DecryptFinal(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV Go_DigestInit(CK_SESSION_HANDLE,CK_MECHANISM_PTR);
CK_RV Go_Digest(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV Go_DigestUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG);
CK_RV Go_DigestKey(CK_SESSION_HANDLE,CK_OBJECT_HANDLE);
CK_RV Go_DigestFinal(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV Go_SignInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
CK_RV Go_SignUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
CK_RV Go_Sign(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV Go_SignFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV Go_SignRecoverInit(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE);
CK_RV Go_SignRecover(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV Go_VerifyInit(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE);
CK_RV Go_Verify(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG);
CK_RV Go_VerifyUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG);
CK_RV Go_VerifyFinal(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG);
CK_RV Go_VerifyRecoverInit(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE);
CK_RV Go_VerifyRecover(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV Go_DigestEncryptUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV Go_DecryptDigestUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV Go_SignEncryptUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV Go_DecryptVerifyUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV Go_GenerateKey(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR);
CK_RV Go_GenerateKeyPair(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_ATTRIBUTE_PTR,CK_ULONG,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR,CK_OBJECT_HANDLE_PTR);
CK_RV Go_WrapKey(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE,CK_OBJECT_HANDLE,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV Go_UnwrapKey(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR);
CK_RV Go_DeriveKey(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR);
CK_RV Go_SeedRandom(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG);
CK_RV Go_GenerateRandom(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG);
CK_RV Go_WaitForSlotEvent(CK_FLAGS,CK_SLOT_ID_PTR,CK_VOID_PTR);
void GoLog(const char*);

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

CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	return Go_Initialize();
}


CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	return Go_Finalize();
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	// Handle packing compatibility for Go.
	// Based on CK_RV GetInfo in pkcs11.go from miekg/pkcs11

	ckInfo Go_Info;
	CK_RV ret = Go_GetInfo(&Go_Info);

	pInfo->cryptokiVersion = Go_Info.cryptokiVersion;
	memcpy(pInfo->manufacturerID, Go_Info.manufacturerID, sizeof(pInfo->manufacturerID));
	pInfo->flags = Go_Info.flags;
	memcpy(pInfo->libraryDescription, Go_Info.libraryDescription, sizeof(pInfo->libraryDescription));
	pInfo->libraryVersion = Go_Info.libraryVersion;

	return ret;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (NULL == ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &pkcs11_functions;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	return Go_GetSlotList(tokenPresent, pSlotList, pulCount);
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	return Go_GetSlotInfo(slotID, pInfo);
}


CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	return Go_GetTokenInfo(slotID, pInfo);
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	return Go_GetMechanismList(slotID, pMechanismList, pulCount);
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	return Go_GetMechanismInfo(slotID, type, pInfo);
}


CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	return Go_InitPIN(hSession, pPin, ulPinLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	return Go_SetPIN(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	return Go_OpenSession(slotID, flags, phSession);
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
	return Go_CloseSession(hSession);
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{	
	return Go_CloseAllSessions(slotID);
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	return Go_GetSessionInfo(hSession, pInfo);
}


CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	return Go_GetOperationState(hSession, pOperationState, pulOperationStateLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{

	return Go_SetOperationState(hSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	return Go_Login(hSession, userType, pPin, ulPinLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{	
	return Go_Logout(hSession);
}


CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	return Go_CreateObject(hSession, pTemplate, ulCount, phObject);
}


CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	return Go_CopyObject(hSession, hObject, pTemplate, ulCount, phNewObject);
}


CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	return Go_DestroyObject(hSession, hObject);
}


CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	return Go_GetObjectSize(hSession, hObject, pulSize);
}


CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	return Go_GetAttributeValue(hSession, hObject, pTemplate, ulCount);
}


CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	return Go_SetAttributeValue(hSession, hObject, pTemplate, ulCount);
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	return Go_FindObjectsInit(hSession, pTemplate, ulCount);
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	return Go_FindObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount);
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
	return Go_FindObjectsFinal(hSession);
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return Go_EncryptInit(hSession, pMechanism, hKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	return Go_Encrypt(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	return Go_EncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	return Go_EncryptFinal(hSession, pLastEncryptedPart, pulLastEncryptedPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return Go_DecryptInit(hSession, pMechanism, hKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	return Go_Decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return Go_DecryptUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	return Go_DecryptFinal(hSession, pLastPart, pulLastPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	return Go_DigestInit(hSession, pMechanism);
}


CK_DEFINE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	return Go_Digest(hSession, pData, ulDataLen, pDigest, pulDigestLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return Go_DigestUpdate(hSession, pPart, ulPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	return Go_DigestKey(hSession, hKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	return Go_DigestFinal(hSession, pDigest, pulDigestLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return Go_SignInit(hSession, pMechanism, hKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	return Go_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return Go_SignUpdate(hSession, pPart, ulPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	return Go_SignFinal(hSession, pSignature, pulSignatureLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return Go_SignRecoverInit(hSession, pMechanism, hKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	return Go_SignRecover(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return Go_VerifyInit(hSession, pMechanism, hKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	return Go_Verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	return Go_VerifyUpdate(hSession, pPart, ulPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	return Go_VerifyFinal(hSession, pSignature, ulSignatureLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return Go_VerifyRecoverInit(hSession, pMechanism, hKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	return Go_VerifyRecover(hSession, pSignature, ulSignatureLen, pData, pulDataLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	return Go_DigestEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return Go_DecryptDigestUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	return Go_SignEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	return Go_DecryptVerifyUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	return Go_GenerateKey(hSession, pMechanism, pTemplate, ulCount, phKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	return Go_GenerateKeyPair(hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	return Go_WrapKey(hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	return Go_UnwrapKey(hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttributeCount, phKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	return Go_DeriveKey(hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey);
}


CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	return Go_SeedRandom(hSession, pSeed, ulSeedLen);
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	return Go_GenerateRandom(hSession, RandomData, ulRandomLen);
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
	return Go_WaitForSlotEvent(flags, pSlot, pReserved);
}
