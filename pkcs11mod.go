// Copyright 2018 Namecoin Developers LGPLv3+

package pkcs11mod

/*
#cgo windows CFLAGS: -DPACKED_STRUCTURES
#cgo windows LDFLAGS: -lpkcs11_exported -L .
#cgo linux LDFLAGS: -lpkcs11_exported -ldl -L .
#cgo darwin CFLAGS: -I/usr/local/share/libtool
#cgo darwin LDFLAGS: -lpkcs11_exported -L/usr/local/lib/ -L .
#cgo openbsd CFLAGS: -I/usr/local/include/
#cgo openbsd LDFLAGS: -lpkcs11_exported -L/usr/local/lib/ -L .
#cgo freebsd CFLAGS: -I/usr/local/include/
#cgo freebsd LDFLAGS: -lpkcs11_exported -L/usr/local/lib/ -L .
#cgo LDFLAGS: -lpkcs11_exported -L .

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "spec/pkcs11go.h"
*/
import "C"

import (
	"io"
	"log"
	"os"
	"unsafe"

	"github.com/miekg/pkcs11"
)

var logfile io.Closer
var backend Backend

func init() {
	f, err := os.OpenFile(os.Getenv("HOME")+"/pkcs11mod.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Printf("error opening file (will try fallback): %v", err)
		f, err = os.OpenFile("./pkcs11mod.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	}
	if err != nil {
		log.Printf("error opening file (will try fallback): %v", err)
		f, err = os.OpenFile(os.Getenv("APPDATA")+"/pkcs11mod.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	}
	if err != nil {
		log.Printf("error opening file (will fallback to console logging): %v", err)
	}
	if err == nil {
		log.SetOutput(f)
		logfile = f
	}
	log.Println("Namecoin PKCS#11 module loading")
}

func SetBackend(b Backend) {
	backend = b
}

//export GoLog
func GoLog(s unsafe.Pointer) {
	log.Println(C.GoString((*C.char)(s)))
}

//export Go_Initialize
func Go_Initialize() C.CK_RV {
	err := backend.Initialize()
	return fromError(err)
}

//export Go_Finalize
func Go_Finalize() C.CK_RV {
	err := backend.Finalize()
	return fromError(err)
}

//export Go_GetInfo
func Go_GetInfo(p C.ckInfoPtr) C.CK_RV {
	if (p == nil) {
		return C.CKR_ARGUMENTS_BAD;
	}

	info, err := backend.GetInfo()
	if err != nil {
		return fromError(err)
	}

	p.cryptokiVersion.major = C.CK_BYTE(info.CryptokiVersion.Major)
	p.cryptokiVersion.minor = C.CK_BYTE(info.CryptokiVersion.Minor)
	p.flags = C.CK_FLAGS(info.Flags)
	p.libraryVersion.major = C.CK_BYTE(info.LibraryVersion.Major)
	p.libraryVersion.minor = C.CK_BYTE(info.LibraryVersion.Minor)

	// CK_INFO strings have a max length of 32, as per Sec. 3.1 of the
	// PKCS#11 spec.
	if len(info.ManufacturerID) > 32 {
		info.ManufacturerID = info.ManufacturerID[:32]
	}
	if len(info.LibraryDescription) > 32 {
		info.LibraryDescription = info.LibraryDescription[:32]
	}

	// CK_INFO strings must be padded with the space character and not
	// null-terminated, as per Sec. 3.1 of the PKCS#11 spec.
	for x := 0; x < 32; x++ {
		p.manufacturerID[x] = C.CK_UTF8CHAR(' ')
		p.libraryDescription[x] = C.CK_UTF8CHAR(' ')
	}

	// Copy the ManufacturerID
	for i, ch := range info.ManufacturerID {
		p.manufacturerID[i] = C.CK_UTF8CHAR(ch)
	}
	// Copy the LibraryDescription
	for i, ch := range info.LibraryDescription {
		p.libraryDescription[i] = C.CK_UTF8CHAR(ch)
	}

	return fromError(err)
}

//export Go_GetSlotList
func Go_GetSlotList(tokenPresent C.CK_BBOOL, pSlotList C.CK_SLOT_ID_PTR, pulCount C.CK_ULONG_PTR) C.CK_RV {
	if (pulCount == nil) {
		return C.CKR_ARGUMENTS_BAD;
	}

	goTokenPresent := fromCBBool(tokenPresent)

	slotList, err := backend.GetSlotList(goTokenPresent)
	if err != nil {
		return fromError(err)
	}

	goCount := uint(len(slotList))

	if pSlotList == nil {
		// Only return the number of slots
		*pulCount = C.CK_ULONG(goCount)
	} else {
		// Return number of slots and list of slots

		// Check to make sure that the buffer is big enough
		goRequestedCount := uint(*pulCount)
		if goRequestedCount < goCount {
			return C.CKR_BUFFER_TOO_SMALL
		}

		*pulCount = C.CK_ULONG(goCount)
		fromList(slotList, C.CK_ULONG_PTR(pSlotList), goCount)
	}

	return fromError(err)
}

//export Go_GetSlotInfo
func Go_GetSlotInfo(slotID C.CK_SLOT_ID, pInfo C.CK_SLOT_INFO_PTR) C.CK_RV {
	if (pInfo == nil) {
		return C.CKR_ARGUMENTS_BAD;
	}

	goSlotID := uint(slotID)

	slotInfo, err := backend.GetSlotInfo(goSlotID)
	if err != nil {
		return fromError(err)
	}

	pInfo.flags = C.CK_FLAGS(slotInfo.Flags)
	pInfo.hardwareVersion.major = C.CK_BYTE(slotInfo.HardwareVersion.Major)
	pInfo.hardwareVersion.minor = C.CK_BYTE(slotInfo.HardwareVersion.Minor)
	pInfo.firmwareVersion.major = C.CK_BYTE(slotInfo.FirmwareVersion.Major)
	pInfo.firmwareVersion.minor = C.CK_BYTE(slotInfo.FirmwareVersion.Minor)

	// CK_SLOT_INFO slotDescription has a max length of 64, as per Sec. 3.2
	// of the PKCS#11 spec.
	if len(slotInfo.SlotDescription) > 64 {
		slotInfo.SlotDescription = slotInfo.SlotDescription[:64]
	}

	// CK_SLOT_INFO manufacturerID has a max length of 32, as per Sec. 3.2
	// of the PKCS#11 spec.
	if len(slotInfo.ManufacturerID) > 32 {
		slotInfo.ManufacturerID = slotInfo.ManufacturerID[:32]
	}

	// CK_SLOT_INFO strings must be padded with the space character and not
	// null-terminated, as per Sec. 3.2 of the PKCS#11 spec.
	for x := 0; x < 64; x++ {
		pInfo.slotDescription[x] = C.CK_UTF8CHAR(' ')
	}
	for x := 0; x < 32; x++ {
		pInfo.manufacturerID[x] = C.CK_UTF8CHAR(' ')
	}

	// Copy the SlotDescription
	for i, ch := range slotInfo.SlotDescription {
		pInfo.slotDescription[i] = C.CK_UTF8CHAR(ch)
	}
	// Copy the ManufacturerID
	for i, ch := range slotInfo.ManufacturerID {
		pInfo.manufacturerID[i] = C.CK_UTF8CHAR(ch)
	}

	return fromError(err)
}

//export Go_GetTokenInfo
func Go_GetTokenInfo(slotID C.CK_SLOT_ID, pInfo C.CK_TOKEN_INFO_PTR) C.CK_RV {
	if (pInfo == nil) {
		return C.CKR_ARGUMENTS_BAD;
	}

	goSlotID := uint(slotID)

	tokenInfo, err := backend.GetTokenInfo(goSlotID)
	if err != nil {
		return fromError(err)
	}

	pInfo.flags = C.CK_FLAGS(tokenInfo.Flags)
	pInfo.ulMaxSessionCount = C.CK_ULONG(tokenInfo.MaxSessionCount)
	pInfo.ulSessionCount = C.CK_ULONG(tokenInfo.SessionCount)
	pInfo.ulMaxRwSessionCount = C.CK_ULONG(tokenInfo.MaxRwSessionCount)
	pInfo.ulRwSessionCount = C.CK_ULONG(tokenInfo.RwSessionCount)
	pInfo.ulMaxPinLen = C.CK_ULONG(tokenInfo.MaxPinLen)
	pInfo.ulMinPinLen = C.CK_ULONG(tokenInfo.MinPinLen)
	pInfo.ulTotalPublicMemory = C.CK_ULONG(tokenInfo.TotalPublicMemory)
	pInfo.ulFreePublicMemory = C.CK_ULONG(tokenInfo.FreePublicMemory)
	pInfo.ulTotalPrivateMemory = C.CK_ULONG(tokenInfo.TotalPrivateMemory)
	pInfo.ulFreePrivateMemory = C.CK_ULONG(tokenInfo.FreePrivateMemory)
	pInfo.hardwareVersion.major = C.CK_BYTE(tokenInfo.HardwareVersion.Major)
	pInfo.hardwareVersion.minor = C.CK_BYTE(tokenInfo.HardwareVersion.Minor)
	pInfo.firmwareVersion.major = C.CK_BYTE(tokenInfo.FirmwareVersion.Major)
	pInfo.firmwareVersion.minor = C.CK_BYTE(tokenInfo.FirmwareVersion.Minor)

	// CK_TOKEN_INFO label has a max length of 32, as per Sec. 3.2 of the
	// PKCS#11 spec.
	if len(tokenInfo.Label) > 32 {
		tokenInfo.Label = tokenInfo.Label[:32]
	}

	// CK_TOKEN_INFO manufacturerID has a max length of 32, as per Sec. 3.2
	// of the PKCS#11 spec.
	if len(tokenInfo.ManufacturerID) > 32 {
		tokenInfo.ManufacturerID = tokenInfo.ManufacturerID[:32]
	}

	// CK_TOKEN_INFO model has a max length of 16, as per Sec. 3.2 of the
	// PKCS#11 spec.
	if len(tokenInfo.Model) > 16 {
		tokenInfo.Model = tokenInfo.Model[:16]
	}

	// CK_TOKEN_INFO serialNumber has a max length of 16, as per Sec. 3.2
	// of the PKCS#11 spec.
	if len(tokenInfo.SerialNumber) > 16 {
		tokenInfo.SerialNumber = tokenInfo.SerialNumber[:16]
	}

	// CK_TOKEN_INFO utcTime has a max length of 16, as per Sec. 3.2 of the
	// PKCS#11 spec.
	if len(tokenInfo.UTCTime) > 16 {
		tokenInfo.UTCTime = tokenInfo.UTCTime[:16]
	}

	// CK_TOKEN_INFO strings must be padded with the space character
	// (except for utcTime which is padded with '0') and not null-
	// terminated, as per Sec. 3.2 of the PKCS#11 spec.
	for x := 0; x < 32; x++ {
		pInfo.label[x] = C.CK_UTF8CHAR(' ')
		pInfo.manufacturerID[x] = C.CK_UTF8CHAR(' ')
	}
	for x := 0; x < 16; x++ {
		pInfo.model[x] = C.CK_UTF8CHAR(' ')
	}
	for x := 0; x < 16; x++ {
		pInfo.serialNumber[x] = C.CK_CHAR(' ')
	}
	for x := 0; x < 16; x++ {
		pInfo.utcTime[x] = C.CK_CHAR('0')
	}

	// Copy the Label
	for i, ch := range tokenInfo.Label {
		pInfo.label[i] = C.CK_UTF8CHAR(ch)
	}
	// Copy the ManufacturerID
	for i, ch := range tokenInfo.ManufacturerID {
		pInfo.manufacturerID[i] = C.CK_UTF8CHAR(ch)
	}
	// Copy the Model
	for i, ch := range tokenInfo.Model {
		pInfo.model[i] = C.CK_UTF8CHAR(ch)
	}
	// Copy the SerialNumber
	for i, ch := range tokenInfo.SerialNumber {
		pInfo.serialNumber[i] = C.CK_CHAR(ch)
	}
	// Copy the UTCTime
	for i, ch := range tokenInfo.UTCTime {
		pInfo.utcTime[i] = C.CK_CHAR(ch)
	}

	return fromError(err)
}

//export Go_GetMechanismList
func Go_GetMechanismList(slotID C.CK_SLOT_ID, pMechanismList C.CK_MECHANISM_TYPE_PTR, pulCount C.CK_ULONG_PTR) C.CK_RV {
	if (pulCount == nil) {
		return C.CKR_ARGUMENTS_BAD;
	}

	goSlotID := uint(slotID)

	mechanismList, err := backend.GetMechanismList(goSlotID)
	if err != nil {
		return fromError(err)
	}

	goCount := uint(len(mechanismList))

	if pMechanismList == nil {
		// Only return the number of mechanisms
		*pulCount = C.CK_ULONG(goCount)
	} else {
		// Return number of mechanisms and list of mechanisms

		// Check to make sure that the buffer is big enough
		goRequestedCount := uint(*pulCount)
		if goRequestedCount < goCount {
			return C.CKR_BUFFER_TOO_SMALL
		}

		*pulCount = C.CK_ULONG(goCount)
		fromMechanismList(mechanismList, C.CK_ULONG_PTR(pMechanismList), goCount)
	}

	return fromError(err)
}

//export Go_OpenSession
func Go_OpenSession(slotID C.CK_SLOT_ID, flags C.CK_FLAGS, phSession C.CK_SESSION_HANDLE_PTR) C.CK_RV {
	if (phSession == nil) {
		return C.CKR_ARGUMENTS_BAD;
	}

	goSlotID := uint(slotID)
	goFlags := uint(flags)

	sessionHandle, err := backend.OpenSession(goSlotID, goFlags)
	if err != nil {
		return fromError(err)
	}

	*phSession = C.CK_SESSION_HANDLE(sessionHandle)

	return fromError(err)
}

//export Go_CloseSession
func Go_CloseSession(sessionHandle C.CK_SESSION_HANDLE) C.CK_RV {
	goSessionHandle := pkcs11.SessionHandle(sessionHandle)

	err := backend.CloseSession(goSessionHandle)
	return fromError(err)
}

//export Go_Login
func Go_Login(sessionHandle C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG) C.CK_RV {
	if (pPin == nil) {
		return C.CKR_ARGUMENTS_BAD;
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goUserType := uint(userType)
	goPin := string(C.GoBytes(unsafe.Pointer(pPin), C.int(ulPinLen)))

	err := backend.Login(goSessionHandle, goUserType, goPin)
	return fromError(err)
}

//export Go_Logout
func Go_Logout(sessionHandle C.CK_SESSION_HANDLE) C.CK_RV {
	goSessionHandle := pkcs11.SessionHandle(sessionHandle)

	err := backend.Logout(goSessionHandle)
	return fromError(err)
}

//export Go_GetObjectSize
func Go_GetObjectSize(sessionHandle C.CK_SESSION_HANDLE, objectHandle C.CK_OBJECT_HANDLE, pulSize C.CK_ULONG_PTR) C.CK_RV {
	if (pulSize == nil) {
		return C.CKR_ARGUMENTS_BAD;
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goObjectHandle := pkcs11.ObjectHandle(objectHandle)

	goSize, err := backend.GetObjectSize(goSessionHandle, goObjectHandle)
	if err != nil {
		return fromError(err)
	}

	*pulSize = C.CK_ULONG(goSize)

	return fromError(err)
}

//export Go_GetAttributeValue
func Go_GetAttributeValue(sessionHandle C.CK_SESSION_HANDLE, objectHandle C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) C.CK_RV {
	if (pTemplate == nil && ulCount > 0) {
		return C.CKR_ARGUMENTS_BAD;
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goObjectHandle := pkcs11.ObjectHandle(objectHandle)
	goTemplate := toTemplate(pTemplate, ulCount)

	goResults, err := backend.GetAttributeValue(goSessionHandle, goObjectHandle, goTemplate)
	if err != nil {
		return fromError(err)
	}

	err = fromTemplate(goResults, pTemplate)
	return fromError(err)
}

//export Go_FindObjectsInit
func Go_FindObjectsInit(sessionHandle C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) C.CK_RV {
	if (pTemplate == nil && ulCount > 0) {
		return C.CKR_ARGUMENTS_BAD;
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goTemplate := toTemplate(pTemplate, ulCount)

	err := backend.FindObjectsInit(goSessionHandle, goTemplate)
	return fromError(err)
}

//export Go_FindObjects
func Go_FindObjects(sessionHandle C.CK_SESSION_HANDLE, phObject C.CK_OBJECT_HANDLE_PTR, ulMaxObjectCount C.CK_ULONG, pulObjectCount C.CK_ULONG_PTR) C.CK_RV {
	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goMax := int(ulMaxObjectCount)

	if (phObject == nil && goMax > 0) {
		return C.CKR_ARGUMENTS_BAD;
	}
	if (pulObjectCount == nil) {
		return C.CKR_ARGUMENTS_BAD;
	}

	objectHandles, _, err := backend.FindObjects(goSessionHandle, goMax)
	if err != nil {
		return fromError(err)
	}

	goCount := uint(len(objectHandles))
	*pulObjectCount = C.CK_ULONG(goCount)
	fromObjectHandleList(objectHandles, C.CK_ULONG_PTR(phObject), goCount)

	return fromError(err)
}

//export Go_FindObjectsFinal
func Go_FindObjectsFinal(sessionHandle C.CK_SESSION_HANDLE) C.CK_RV {
	goSessionHandle := pkcs11.SessionHandle(sessionHandle)

	err := backend.FindObjectsFinal(goSessionHandle)
	return fromError(err)
}
