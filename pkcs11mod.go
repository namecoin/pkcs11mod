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
	"sync"
	"unsafe"

	"github.com/miekg/pkcs11"
)

var trace bool
var traceSensitive bool

var logfile io.Closer
var backend Backend

func init() {
	dir, err := os.UserConfigDir()
	if err != nil {
		log.Printf("error reading config dir (will try fallback): %v", err)

		dir = "."
	}

	f, err := os.OpenFile(dir+"/pkcs11mod.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Printf("error opening file (will try fallback): %v", err)

		dir = "."
		f, err = os.OpenFile(dir+"/pkcs11mod.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	}

	if err != nil {
		log.Printf("error opening file (will fallback to console logging): %v", err)
	}

	if err == nil {
		log.SetOutput(f)
		logfile = f
	}

	log.Println("Namecoin PKCS#11 module loading")

	if os.Getenv("PKCS11MOD_TRACE") == "1" {
		trace = true
	}

	if os.Getenv("PKCS11MOD_TRACE_SENSITIVE") == "1" {
		traceSensitive = true
	}

	preventUnload()
}

func SetBackend(b Backend) {
	backend = b
}

//export goLog
func goLog(s unsafe.Pointer) {
	log.Println(C.GoString((*C.char)(s)))
}

//export goInitialize
func goInitialize() C.CK_RV {
	if backend == nil {
		log.Println("pkcs11mod: Can't initialize nil backend")
		return C.CKR_GENERAL_ERROR
	}

	if trace {
		log.Println("pkcs11mod Initialize")
	}

	err := backend.Initialize()

	return fromError(err)
}

//export goFinalize
func goFinalize() C.CK_RV {
	if trace {
		log.Println("pkcs11mod Finalize")
	}

	err := backend.Finalize()

	exitSoon()

	return fromError(err)
}

//export goGetInfo
func goGetInfo(p C.ckInfoPtr) C.CK_RV {
	if p == nil {
		return C.CKR_ARGUMENTS_BAD
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

	return fromError(nil)
}

//export goGetSlotList
func goGetSlotList(tokenPresent C.CK_BBOOL, pSlotList C.CK_SLOT_ID_PTR, pulCount C.CK_ULONG_PTR) C.CK_RV {
	if pulCount == nil {
		return C.CKR_ARGUMENTS_BAD
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

	return fromError(nil)
}

//export goGetSlotInfo
func goGetSlotInfo(slotID C.CK_SLOT_ID, pInfo C.CK_SLOT_INFO_PTR) C.CK_RV {
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
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

	return fromError(nil)
}

//export goGetTokenInfo
func goGetTokenInfo(slotID C.CK_SLOT_ID, pInfo C.CK_TOKEN_INFO_PTR) C.CK_RV {
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
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

//export goGetMechanismList
func goGetMechanismList(slotID C.CK_SLOT_ID, pMechanismList C.CK_MECHANISM_TYPE_PTR, pulCount C.CK_ULONG_PTR) C.CK_RV {
	if pulCount == nil {
		return C.CKR_ARGUMENTS_BAD
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

	return fromError(nil)
}

//export goGetMechanismInfo
func goGetMechanismInfo(slotID C.CK_SLOT_ID, mechType C.CK_MECHANISM_TYPE, pInfo C.CK_MECHANISM_INFO_PTR) C.CK_RV {
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSlotID := uint(slotID)
	goMechType := uint(mechType)

	m := []*pkcs11.Mechanism{
		{
			Mechanism: goMechType,
		},
	}

	mi, err := backend.GetMechanismInfo(goSlotID, m)
	if err != nil {
		return fromError(err)
	}

	pInfo.ulMinKeySize = C.CK_ULONG(mi.MinKeySize)
	pInfo.ulMaxKeySize = C.CK_ULONG(mi.MaxKeySize)
	pInfo.flags = C.CK_FLAGS(mi.Flags)

	return fromError(nil)
}

//export goInitPIN
func goInitPIN(sessionHandle C.CK_SESSION_HANDLE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG) C.CK_RV {
	if pPin == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goPin := string((*[1 << 30]byte)(unsafe.Pointer(pPin))[:ulPinLen:ulPinLen])

	err := backend.InitPIN(goSessionHandle, goPin)

	return fromError(err)
}

//export goSetPIN
func goSetPIN(sessionHandle C.CK_SESSION_HANDLE, pOldPin C.CK_UTF8CHAR_PTR, ulOldLen C.CK_ULONG, pNewPin C.CK_UTF8CHAR_PTR, ulNewLen C.CK_ULONG) C.CK_RV {
	if pOldPin == nil || pNewPin == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goOldPin := string(C.GoBytes(unsafe.Pointer(pOldPin), C.int(ulOldLen)))
	goNewPin := string(C.GoBytes(unsafe.Pointer(pNewPin), C.int(ulNewLen)))

	err := backend.SetPIN(goSessionHandle, goOldPin, goNewPin)
	return fromError(err)
}

type sessionInfo struct {
	encryptData []byte
	decryptData []byte
	digestData  []byte
	signData    []byte
}

var sessions = map[pkcs11.SessionHandle]*sessionInfo{}
var sessionsMutex sync.RWMutex

//export goOpenSession
func goOpenSession(slotID C.CK_SLOT_ID, flags C.CK_FLAGS, phSession C.CK_SESSION_HANDLE_PTR) C.CK_RV {
	if phSession == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSlotID := uint(slotID)
	goFlags := uint(flags)

	sessionHandle, err := backend.OpenSession(goSlotID, goFlags)
	if err != nil {
		return fromError(err)
	}

	sessionsMutex.Lock()
	sessions[sessionHandle] = &sessionInfo{}
	sessionsMutex.Unlock()

	*phSession = C.CK_SESSION_HANDLE(sessionHandle)
	return fromError(nil)
}

//export goCloseSession
func goCloseSession(sessionHandle C.CK_SESSION_HANDLE) C.CK_RV {
	goSessionHandle := pkcs11.SessionHandle(sessionHandle)

	err := backend.CloseSession(goSessionHandle)
	return fromError(err)
}

//export goCloseAllSessions
func goCloseAllSessions(slotID C.CK_SLOT_ID) C.CK_RV {
	goSlotID := uint(slotID)

	err := backend.CloseAllSessions(goSlotID)
	return fromError(err)
}

//export goGetOperationState
func goGetOperationState(sessionHandle C.CK_SESSION_HANDLE, pOperationState C.CK_BYTE_PTR, pulOperationStateLen C.CK_ULONG_PTR) C.CK_RV {
	if pOperationState == nil || pulOperationStateLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goOperationState := (*[1 << 30]byte)(unsafe.Pointer(pOperationState))[:*pulOperationStateLen:*pulOperationStateLen]

	result, err := backend.GetOperationState(goSessionHandle)
	if err != nil {
		return fromError(err)
	}

	if int(*pulOperationStateLen) < len(result) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	copy(goOperationState, result)
	*pulOperationStateLen = C.CK_ULONG(len(result))
	return fromError(nil)
}

//export goSetOperationState
func goSetOperationState(sessionHandle C.CK_SESSION_HANDLE, pOperationState C.CK_BYTE_PTR, ulOperationStateLen C.CK_LONG, hEncryptionKey C.CK_OBJECT_HANDLE, hAuthenticationKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if pOperationState == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goEncryptionKey := pkcs11.ObjectHandle(hEncryptionKey)
	goAuthenticationKey := pkcs11.ObjectHandle(hAuthenticationKey)
	goOperationState := C.GoBytes(unsafe.Pointer(pOperationState), C.int(ulOperationStateLen))

	err := backend.SetOperationState(goSessionHandle, goOperationState, goEncryptionKey, goAuthenticationKey)
	return fromError(err)
}

//export goGetSessionInfo
func goGetSessionInfo(sessionHandle C.CK_SESSION_HANDLE, pInfo C.CK_SESSION_INFO_PTR) C.CK_RV {
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)

	info, err := backend.GetSessionInfo(goSessionHandle)
	if err != nil {
		return fromError(err)
	}

	pInfo.slotID = C.CK_SLOT_ID(info.SlotID)
	pInfo.state = C.CK_STATE(info.State)
	pInfo.flags = C.CK_FLAGS(info.Flags)
	pInfo.ulDeviceError = C.CK_ULONG(info.DeviceError)
	return fromError(nil)
}

//export goLogin
func goLogin(sessionHandle C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG) C.CK_RV {
	if pPin == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goUserType := uint(userType)
	goPin := string(C.GoBytes(unsafe.Pointer(pPin), C.int(ulPinLen)))

	err := backend.Login(goSessionHandle, goUserType, goPin)
	return fromError(err)
}

//export goLogout
func goLogout(sessionHandle C.CK_SESSION_HANDLE) C.CK_RV {
	goSessionHandle := pkcs11.SessionHandle(sessionHandle)

	err := backend.Logout(goSessionHandle)
	return fromError(err)
}

//export goCreateObject
func goCreateObject(sessionHandle C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG, phObject C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	if pTemplate == nil && ulCount > 0 || phObject == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goTemplate := toTemplate(pTemplate, ulCount)

	goHandle, err := backend.CreateObject(goSessionHandle, goTemplate)
	if err != nil {
		return fromError(err)
	}

	*phObject = C.CK_OBJECT_HANDLE(goHandle)
	return fromError(nil)
}

//export goCopyObject
func goCopyObject(sessionHandle C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG, phNewObject C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	if pTemplate == nil && ulCount > 0 || phNewObject == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goTemplate := toTemplate(pTemplate, ulCount)
	goObjectHandle := pkcs11.ObjectHandle(hObject)

	goHandle, err := backend.CopyObject(goSessionHandle, goObjectHandle, goTemplate)
	if err != nil {
		return fromError(err)
	}

	*phNewObject = C.CK_OBJECT_HANDLE(goHandle)
	return fromError(nil)
}

//export goDestroyObject
func goDestroyObject(sessionHandle C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE) C.CK_RV {
	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goObjectHandle := pkcs11.ObjectHandle(hObject)

	err := backend.DestroyObject(goSessionHandle, goObjectHandle)
	return fromError(err)
}

//export goGetObjectSize
func goGetObjectSize(sessionHandle C.CK_SESSION_HANDLE, objectHandle C.CK_OBJECT_HANDLE, pulSize C.CK_ULONG_PTR) C.CK_RV {
	if pulSize == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goObjectHandle := pkcs11.ObjectHandle(objectHandle)

	goSize, err := backend.GetObjectSize(goSessionHandle, goObjectHandle)
	if err != nil {
		return fromError(err)
	}

	*pulSize = C.CK_ULONG(goSize)
	return fromError(nil)
}

//export goGetAttributeValue
func goGetAttributeValue(sessionHandle C.CK_SESSION_HANDLE, objectHandle C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) C.CK_RV {
	if pTemplate == nil && ulCount > 0 {
		if trace {
			log.Println("pkcs11mod GetAttributeValue: CKR_ARGUMENTS_BAD")
		}

		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goObjectHandle := pkcs11.ObjectHandle(objectHandle)
	goTemplate := toTemplate(pTemplate, ulCount)

	goResults, errFinal := backend.GetAttributeValue(goSessionHandle, goObjectHandle, goTemplate)
	if fromError(errFinal) == pkcs11.CKR_ATTRIBUTE_SENSITIVE || fromError(errFinal) == pkcs11.CKR_ATTRIBUTE_TYPE_INVALID {
		// If we get these error codes in a one-shot, we need to try the
		// attributes one-by-one to retrieve partial results.
		goResults = make([]*pkcs11.Attribute, len(goTemplate))

		for i, t := range goTemplate {
			goTemplateSingle := []*pkcs11.Attribute{t}

			goResultsSingle, err := backend.GetAttributeValue(goSessionHandle, goObjectHandle, goTemplateSingle)

			switch {
			case fromError(err) == pkcs11.CKR_ATTRIBUTE_SENSITIVE || fromError(err) == pkcs11.CKR_ATTRIBUTE_TYPE_INVALID:
				goResults[i] = &pkcs11.Attribute{
					Type:  t.Type,
					Value: nil,
				}
			case err != nil:
				if trace {
					log.Printf("pkcs11mod GetAttributeValue: %v", err)
				}

				return fromError(err)
			default:
				goResults[i] = goResultsSingle[0]
			}
		}
	} else if errFinal != nil {
		if trace {
			log.Printf("pkcs11mod GetAttributeValue: %v", errFinal)
		}

		return fromError(errFinal)
	}

	errFromTemplate := fromTemplate(goResults, pTemplate)
	if errFromTemplate != nil {
		errFinal = errFromTemplate
	}

	if trace {
		log.Printf("pkcs11mod GetAttributeValue: %v", errFinal)
	}

	return fromError(errFinal)
}

//export goSetAttributeValue
func goSetAttributeValue(sessionHandle C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) C.CK_RV {
	if pTemplate == nil && ulCount > 0 {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goObjectHandle := pkcs11.ObjectHandle(hObject)
	goTemplate := toTemplate(pTemplate, ulCount)

	err := backend.SetAttributeValue(goSessionHandle, goObjectHandle, goTemplate)
	return fromError(err)
}

//export goFindObjectsInit
func goFindObjectsInit(sessionHandle C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) C.CK_RV {
	if trace {
		log.Println("pkcs11mod FindObjectsInit")
	}

	if pTemplate == nil && ulCount > 0 {
		if trace {
			log.Println("pkcs11mod FindObjectsInit: CKR_ARGUMENTS_BAD")
		}

		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goTemplate := toTemplate(pTemplate, ulCount)

	if trace {
		for _, attr := range goTemplate {
			log.Printf("pkcs11mod FindObjectsInit: template %s", AttrTrace(attr))
		}
	}

	err := backend.FindObjectsInit(goSessionHandle, goTemplate)
	return fromError(err)
}

//export goFindObjects
func goFindObjects(sessionHandle C.CK_SESSION_HANDLE, phObject C.CK_OBJECT_HANDLE_PTR, ulMaxObjectCount C.CK_ULONG, pulObjectCount C.CK_ULONG_PTR) C.CK_RV {
	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goMax := int(ulMaxObjectCount)

	if (phObject == nil && goMax > 0) || pulObjectCount == nil {
		if trace {
			log.Println("pkcs11mod FindObjects: CKR_ARGUMENTS_BAD")
		}

		return C.CKR_ARGUMENTS_BAD
	}

	objectHandles, _, err := backend.FindObjects(goSessionHandle, goMax)
	if err != nil {
		if trace {
			log.Printf("pkcs11mod FindObjects: %v", err)
		}

		return fromError(err)
	}

	if trace {
		log.Printf("pkcs11mod FindObjects: %d objects returned", len(objectHandles))
	}

	goCount := uint(len(objectHandles))
	*pulObjectCount = C.CK_ULONG(goCount)
	fromObjectHandleList(objectHandles, C.CK_ULONG_PTR(phObject), goCount)
	return fromError(nil)
}

//export goFindObjectsFinal
func goFindObjectsFinal(sessionHandle C.CK_SESSION_HANDLE) C.CK_RV {
	goSessionHandle := pkcs11.SessionHandle(sessionHandle)

	err := backend.FindObjectsFinal(goSessionHandle)
	return fromError(err)
}

//export goEncryptInit
func goEncryptInit(sessionHandle C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goObjectHandle := pkcs11.ObjectHandle(hKey)
	goMechanism := toMechanism(pMechanism)

	err := backend.EncryptInit(goSessionHandle, []*pkcs11.Mechanism{goMechanism}, goObjectHandle)
	return fromError(err)
}

//export goEncrypt
func goEncrypt(sessionHandle C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pEncryptedData C.CK_BYTE_PTR, pulEncryptedDataLen C.CK_ULONG_PTR) C.CK_RV {
	if pData == nil || pulEncryptedDataLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goData := C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))

	var (
		encryptedData []byte
		err           error
	)

	sessionsMutex.RLock()
	session, ok := sessions[goSessionHandle]
	sessionsMutex.RUnlock()
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}

	if pEncryptedData == nil {
		encryptedData, err = backend.Encrypt(goSessionHandle, goData)
		if err != nil {
			return fromError(err)
		}

		session.encryptData = encryptedData

		size := len(encryptedData)
		*pulEncryptedDataLen = C.CK_ULONG(size)
		return fromError(nil)
	}

	goEncryptedData := (*[1 << 30]byte)(unsafe.Pointer(pEncryptedData))[:*pulEncryptedDataLen:*pulEncryptedDataLen]

	encryptedData = session.encryptData
	if encryptedData != nil {
		session.encryptData = nil
	} else {
		encryptedData, err = backend.Encrypt(goSessionHandle, goData)
		if err != nil {
			return fromError(err)
		}
	}

	if int(*pulEncryptedDataLen) < len(encryptedData) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	copy(goEncryptedData, encryptedData)
	*pulEncryptedDataLen = C.CK_ULONG(len(encryptedData))
	return fromError(nil)
}

//export goEncryptUpdate
func goEncryptUpdate(sessionHandle C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) C.CK_RV {
	if pPart == nil || pEncryptedPart == nil || pulEncryptedPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goData := C.GoBytes(unsafe.Pointer(pPart), C.int(ulPartLen))
	goEncryptedPart := (*[1 << 30]byte)(unsafe.Pointer(pEncryptedPart))[:*pulEncryptedPartLen:*pulEncryptedPartLen]

	encryptedPart, err := backend.Encrypt(goSessionHandle, goData)
	if err != nil {
		return fromError(err)
	}

	if int(*pulEncryptedPartLen) < len(encryptedPart) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	copy(goEncryptedPart, encryptedPart)
	*pulEncryptedPartLen = C.CK_ULONG(len(encryptedPart))
	return fromError(nil)
}

//export goEncryptFinal
func goEncryptFinal(sessionHandle C.CK_SESSION_HANDLE, pLastEncryptedPart C.CK_BYTE_PTR, pulLastEncryptedPartLen C.CK_ULONG_PTR) C.CK_RV {
	if pLastEncryptedPart == nil || pulLastEncryptedPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goLastEncryptedPart := (*[1 << 30]byte)(unsafe.Pointer(pLastEncryptedPart))[:*pulLastEncryptedPartLen:*pulLastEncryptedPartLen]

	lastEncryptedPart, err := backend.EncryptFinal(goSessionHandle)
	if err != nil {
		return fromError(err)
	}

	if int(*pulLastEncryptedPartLen) < len(lastEncryptedPart) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	copy(goLastEncryptedPart, lastEncryptedPart)
	*pulLastEncryptedPartLen = C.CK_ULONG(len(lastEncryptedPart))
	return fromError(nil)
}

//export goDecryptInit
func goDecryptInit(sessionHandle C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goObjectHandle := pkcs11.ObjectHandle(hKey)
	goMechanism := toMechanism(pMechanism)

	err := backend.DecryptInit(goSessionHandle, []*pkcs11.Mechanism{goMechanism}, goObjectHandle)
	return fromError(err)
}

//export goDecrypt
func goDecrypt(sessionHandle C.CK_SESSION_HANDLE, pEncryptedData C.CK_BYTE_PTR, ulEncryptedDataLen C.CK_ULONG, pData C.CK_BYTE_PTR, pulDataLen C.CK_ULONG_PTR) C.CK_RV {
	if pEncryptedData == nil || pulDataLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goEncryptedData := C.GoBytes(unsafe.Pointer(pEncryptedData), C.int(ulEncryptedDataLen))

	var (
		data []byte
		err  error
	)

	sessionsMutex.RLock()
	session, ok := sessions[goSessionHandle]
	sessionsMutex.RUnlock()
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}

	if pData == nil {
		data, err = backend.Decrypt(goSessionHandle, goEncryptedData)
		if err != nil {
			return fromError(err)
		}

		session.decryptData = data

		size := len(data)
		*pulDataLen = C.CK_ULONG(size)
		return fromError(nil)
	}

	goData := (*[1 << 30]byte)(unsafe.Pointer(pData))[:*pulDataLen:*pulDataLen]

	data = session.decryptData
	if data != nil {
		session.decryptData = nil
	} else {
		data, err = backend.Decrypt(goSessionHandle, goEncryptedData)
		if err != nil {
			return fromError(err)
		}
	}

	if int(*pulDataLen) < len(data) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	copy(goData, data)
	*pulDataLen = C.CK_ULONG(len(data))
	return fromError(nil)
}

//export goDecryptUpdate
func goDecryptUpdate(sessionHandle C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) C.CK_RV {
	if pEncryptedPart == nil || pPart == nil || pulPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goData := C.GoBytes(unsafe.Pointer(pPart), C.int(ulEncryptedPartLen))
	goPart := (*[1 << 30]byte)(unsafe.Pointer(pPart))[:*pulPartLen:*pulPartLen]

	decryptedPart, err := backend.Decrypt(goSessionHandle, goData)
	if err != nil {
		return fromError(err)
	}

	if int(*pulPartLen) < len(decryptedPart) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	copy(goPart, decryptedPart)
	*pulPartLen = C.CK_ULONG(len(decryptedPart))
	return fromError(nil)
}

//export goDecryptFinal
func goDecryptFinal(sessionHandle C.CK_SESSION_HANDLE, pLastPart C.CK_BYTE_PTR, pulLastPartLen C.CK_ULONG_PTR) C.CK_RV {
	if pLastPart == nil || pulLastPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goLastPart := (*[1 << 30]byte)(unsafe.Pointer(pLastPart))[:*pulLastPartLen:*pulLastPartLen]

	lastDataPart, err := backend.DecryptFinal(goSessionHandle)
	if err != nil {
		return fromError(err)
	}

	if int(*pulLastPartLen) < len(lastDataPart) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	copy(goLastPart, lastDataPart)
	*pulLastPartLen = C.CK_ULONG(len(lastDataPart))
	return fromError(err)
}

//export goDigestInit
func goDigestInit(sessionHandle C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR) C.CK_RV {
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goMechanism := toMechanism(pMechanism)
	err := backend.DigestInit(goSessionHandle, []*pkcs11.Mechanism{goMechanism})
	return fromError(err)
}

//export goDigest
func goDigest(sessionHandle C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pDigest C.CK_BYTE_PTR, pulDigestLen C.CK_ULONG_PTR) C.CK_RV {
	if pData == nil || pulDigestLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goData := C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))

	var digest []byte
	var err error

	sessionsMutex.RLock()
	session, ok := sessions[goSessionHandle]
	sessionsMutex.RUnlock()
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}

	if pDigest == nil {
		digest, err = backend.Digest(goSessionHandle, goData)
		if err != nil {
			return fromError(err)
		}

		session.digestData = digest

		size := len(digest)
		*pulDigestLen = C.CK_ULONG(size)
		return fromError(nil)
	}
	goDigest := (*[1 << 30]byte)(unsafe.Pointer(pDigest))[:*pulDigestLen:*pulDigestLen]

	digest = session.digestData
	if digest != nil {
		session.digestData = nil
	} else {
		digest, err = backend.Digest(goSessionHandle, goData)
		if err != nil {
			return fromError(err)
		}
	}

	if int(*pulDigestLen) < len(digest) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	copy(goDigest, digest)
	*pulDigestLen = C.CK_ULONG(len(digest))
	return fromError(nil)
}

//export goDigestUpdate
func goDigestUpdate(sessionHandle C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG) C.CK_RV {
	if pPart == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goPart := C.GoBytes(unsafe.Pointer(pPart), C.int(ulPartLen))

	err := backend.DigestUpdate(goSessionHandle, goPart)
	return fromError(err)
}

//export goDigestKey
func goDigestKey(sessionHandle C.CK_SESSION_HANDLE, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goKeyHandle := pkcs11.ObjectHandle(hKey)

	err := backend.DigestKey(goSessionHandle, goKeyHandle)
	return fromError(err)
}

//export goDigestFinal
func goDigestFinal(sessionHandle C.CK_SESSION_HANDLE, pDigest C.CK_BYTE_PTR, pulDigestLen C.CK_ULONG_PTR) C.CK_RV {
	if pDigest == nil || pulDigestLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goDigest := (*[1 << 30]byte)(unsafe.Pointer(pDigest))[:*pulDigestLen:*pulDigestLen]

	digest, err := backend.DigestFinal(goSessionHandle)
	if err != nil {
		return fromError(err)
	}

	if int(*pulDigestLen) < len(digest) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	copy(goDigest, digest)
	*pulDigestLen = C.CK_ULONG(len(digest))
	return fromError(nil)
}

//export goSignInit
func goSignInit(sessionHandle C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goObjectHandle := pkcs11.ObjectHandle(hKey)
	goMechanism := toMechanism(pMechanism)

	err := backend.SignInit(goSessionHandle, []*pkcs11.Mechanism{goMechanism}, goObjectHandle)
	return fromError(err)
}

//export goSign
func goSign(sessionHandle C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV {
	if pData == nil || pulSignatureLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goData := C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))

	var signature []byte
	var err error

	sessionsMutex.RLock()
	session, ok := sessions[goSessionHandle]
	sessionsMutex.RUnlock()
	if !ok {
		return C.CKR_SESSION_HANDLE_INVALID
	}

	if pSignature == nil {
		signature, err = backend.Sign(goSessionHandle, goData)
		if err != nil {
			return fromError(err)
		}

		session.signData = signature

		size := len(signature)
		*pulSignatureLen = C.CK_ULONG(size)
		return fromError(nil)
	}
	goSignature := (*[1 << 30]byte)(unsafe.Pointer(pSignature))[:*pulSignatureLen:*pulSignatureLen]

	signature = session.signData
	if signature != nil {
		session.signData = nil
	} else {
		signature, err = backend.Sign(goSessionHandle, goData)
		if err != nil {
			return fromError(err)
		}
	}

	if int(*pulSignatureLen) < len(signature) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	copy(goSignature, signature)
	*pulSignatureLen = C.CK_ULONG(len(signature))
	return fromError(nil)
}

//export goSignUpdate
func goSignUpdate(sessionHandle C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG) C.CK_RV {
	if pPart == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goPart := C.GoBytes(unsafe.Pointer(pPart), C.int(ulPartLen))

	err := backend.SignUpdate(goSessionHandle, goPart)
	return fromError(err)
}

//export goSignFinal
func goSignFinal(sessionHandle C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV {
	if pSignature == nil || pulSignatureLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goSignature := (*[1 << 30]byte)(unsafe.Pointer(pSignature))[:*pulSignatureLen:*pulSignatureLen]

	signature, err := backend.SignFinal(goSessionHandle)
	if err != nil {
		return fromError(err)
	}

	if int(*pulSignatureLen) < len(signature) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	copy(goSignature, signature)
	*pulSignatureLen = C.CK_ULONG(len(signature))
	return fromError(nil)
}

//export goSignRecoverInit
func goSignRecoverInit(sessionHandle C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goObjectHandle := pkcs11.ObjectHandle(hKey)
	goMechanism := toMechanism(pMechanism)

	err := backend.SignRecoverInit(goSessionHandle, []*pkcs11.Mechanism{goMechanism}, goObjectHandle)
	return fromError(err)
}

//export goSignRecover
func goSignRecover(sessionHandle C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV {
	if pData == nil || pSignature == nil || pulSignatureLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goData := C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))
	goSignature := (*[1 << 30]byte)(unsafe.Pointer(pSignature))[:*pulSignatureLen:*pulSignatureLen]

	signature, err := backend.SignRecover(goSessionHandle, goData)
	if err != nil {
		return fromError(err)
	}

	if int(*pulSignatureLen) < len(signature) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	copy(goSignature, signature)
	*pulSignatureLen = C.CK_ULONG(len(signature))
	return fromError(nil)
}

//export goVerifyInit
func goVerifyInit(sessionHandle C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goObjectHandle := pkcs11.ObjectHandle(hKey)
	goMechanism := toMechanism(pMechanism)

	err := backend.VerifyInit(goSessionHandle, []*pkcs11.Mechanism{goMechanism}, goObjectHandle)
	return fromError(err)
}

//export goVerify
func goVerify(sessionHandle C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) C.CK_RV {
	if pData == nil || pSignature == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goData := C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))
	goSignature := C.GoBytes(unsafe.Pointer(pSignature), C.int(ulSignatureLen))

	err := backend.Verify(goSessionHandle, goData, goSignature)
	return fromError(err)
}

//export goVerifyUpdate
func goVerifyUpdate(sessionHandle C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG) C.CK_RV {
	if pPart == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goPart := C.GoBytes(unsafe.Pointer(pPart), C.int(ulPartLen))

	err := backend.VerifyUpdate(goSessionHandle, goPart)
	return fromError(err)
}

//export goVerifyFinal
func goVerifyFinal(sessionHandle C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) C.CK_RV {
	if pSignature == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goSignature := C.GoBytes(unsafe.Pointer(pSignature), C.int(ulSignatureLen))

	err := backend.VerifyFinal(goSessionHandle, goSignature)
	return fromError(err)
}

//export goVerifyRecoverInit
func goVerifyRecoverInit(sessionHandle C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goObjectHandle := pkcs11.ObjectHandle(hKey)
	goMechanism := toMechanism(pMechanism)

	err := backend.VerifyRecoverInit(goSessionHandle, []*pkcs11.Mechanism{goMechanism}, goObjectHandle)
	return fromError(err)
}

//export goVerifyRecover
func goVerifyRecover(sessionHandle C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG, pData C.CK_BYTE_PTR, pulDataLen C.CK_ULONG_PTR) C.CK_RV {
	if pData == nil || pSignature == nil || pulDataLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goSignature := C.GoBytes(unsafe.Pointer(pSignature), C.int(ulSignatureLen))
	goData := (*[1 << 30]byte)(unsafe.Pointer(pData))[:*pulDataLen:*pulDataLen]

	data, err := backend.VerifyRecover(goSessionHandle, goSignature)
	if err != nil {
		return fromError(err)
	}

	if int(*pulDataLen) < len(data) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	copy(goData, data)
	*pulDataLen = C.CK_ULONG(len(data))
	return fromError(nil)
}

//export goDigestEncryptUpdate
func goDigestEncryptUpdate(sessionHandle C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) C.CK_RV {
	if pPart == nil || pEncryptedPart == nil || pulEncryptedPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goPart := C.GoBytes(unsafe.Pointer(pPart), C.int(ulPartLen))
	goEncryptedPart := (*[1 << 30]byte)(unsafe.Pointer(pEncryptedPart))[:*pulEncryptedPartLen:*pulEncryptedPartLen]

	encryptedPart, err := backend.DigestEncryptUpdate(goSessionHandle, goPart)
	if err != nil {
		return fromError(err)
	}

	if int(*pulEncryptedPartLen) < len(encryptedPart) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	copy(goEncryptedPart, encryptedPart)
	*pulEncryptedPartLen = C.CK_ULONG(len(encryptedPart))
	return fromError(nil)
}

//export goDecryptDigestUpdate
func goDecryptDigestUpdate(sessionHandle C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) C.CK_RV {
	if pPart == nil || pEncryptedPart == nil || pulPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goEncryptedPart := C.GoBytes(unsafe.Pointer(pEncryptedPart), C.int(ulEncryptedPartLen))
	goPart := (*[1 << 30]byte)(unsafe.Pointer(pEncryptedPart))[:*pulPartLen:*pulPartLen]

	part, err := backend.DecryptDigestUpdate(goSessionHandle, goEncryptedPart)
	if err != nil {
		return fromError(err)
	}

	if int(*pulPartLen) < len(part) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	copy(goPart, part)
	*pulPartLen = C.CK_ULONG(len(part))
	return fromError(nil)
}

//export goSignEncryptUpdate
func goSignEncryptUpdate(sessionHandle C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) C.CK_RV {
	if pPart == nil || pEncryptedPart == nil || pulEncryptedPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goPart := C.GoBytes(unsafe.Pointer(pPart), C.int(ulPartLen))
	goEncryptedPart := (*[1 << 30]byte)(unsafe.Pointer(pEncryptedPart))[:*pulEncryptedPartLen:*pulEncryptedPartLen]

	encryptedPart, err := backend.SignEncryptUpdate(goSessionHandle, goPart)
	if err != nil {
		return fromError(err)
	}

	if int(*pulEncryptedPartLen) < len(encryptedPart) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	copy(goEncryptedPart, encryptedPart)
	*pulEncryptedPartLen = C.CK_ULONG(len(encryptedPart))
	return fromError(nil)
}

//export goDecryptVerifyUpdate
func goDecryptVerifyUpdate(sessionHandle C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) C.CK_RV {
	if pPart == nil || pEncryptedPart == nil || pulPartLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goEncryptedPart := C.GoBytes(unsafe.Pointer(pEncryptedPart), C.int(ulEncryptedPartLen))
	goPart := (*[1 << 30]byte)(unsafe.Pointer(pEncryptedPart))[:*pulPartLen:*pulPartLen]

	part, err := backend.DecryptVerifyUpdate(goSessionHandle, goEncryptedPart)
	if err != nil {
		return fromError(err)
	}

	if int(*pulPartLen) < len(part) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	copy(goPart, part)
	*pulPartLen = C.CK_ULONG(len(part))
	return fromError(nil)
}

//export goGenerateKey
func goGenerateKey(sessionHandle C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	if pMechanism == nil || pTemplate == nil && ulCount > 0 || phKey == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goMechanism := toMechanism(pMechanism)
	goTemplate := toTemplate(pTemplate, ulCount)

	keyHandle, err := backend.GenerateKey(goSessionHandle, []*pkcs11.Mechanism{goMechanism}, goTemplate)
	if err != nil {
		return fromError(err)
	}

	*phKey = C.CK_OBJECT_HANDLE(keyHandle)
	return fromError(nil)
}

//export goGenerateKeyPair
func goGenerateKeyPair(sessionHandle C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pPublicKeyTemplate C.CK_ATTRIBUTE_PTR, ulPublicKeyAttributeCount C.CK_ULONG, pPrivateKeyTemplate C.CK_ATTRIBUTE_PTR, ulPrivateKeyAttributeCount C.CK_ULONG, phPublicKey C.CK_OBJECT_HANDLE_PTR, phPrivateKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	if pMechanism == nil || pPublicKeyTemplate == nil || pPrivateKeyTemplate == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goMechanism := toMechanism(pMechanism)
	goPublicTemplate := toTemplate(pPublicKeyTemplate, ulPublicKeyAttributeCount)
	goPrivateTemplate := toTemplate(pPrivateKeyTemplate, ulPrivateKeyAttributeCount)

	pubKeyHandle, privKeyHandle, err := backend.GenerateKeyPair(goSessionHandle, []*pkcs11.Mechanism{goMechanism}, goPublicTemplate, goPrivateTemplate)
	if err != nil {
		return fromError(err)
	}

	*phPublicKey = C.CK_OBJECT_HANDLE(pubKeyHandle)
	*phPrivateKey = C.CK_OBJECT_HANDLE(privKeyHandle)
	return fromError(nil)
}

//export goWrapKey
func goWrapKey(sessionHandle C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hWrappingKey C.CK_OBJECT_HANDLE, hKey C.CK_OBJECT_HANDLE, pWrappedKey C.CK_BYTE_PTR, pulWrappedKeyLen C.CK_ULONG_PTR) C.CK_RV {
	if pMechanism == nil || pWrappedKey == nil || pulWrappedKeyLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goMechanism := toMechanism(pMechanism)
	goWrappingKey := pkcs11.ObjectHandle(hWrappingKey)
	goKeyHandle := pkcs11.ObjectHandle(hKey)
	goWrappedKey := (*[1 << 30]byte)(unsafe.Pointer(pWrappedKey))[:*pulWrappedKeyLen:*pulWrappedKeyLen]

	wrappedKey, err := backend.WrapKey(goSessionHandle, []*pkcs11.Mechanism{goMechanism}, goWrappingKey, goKeyHandle)
	if err != nil {
		return fromError(nil)
	}

	if int(*pulWrappedKeyLen) < len(wrappedKey) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	copy(goWrappedKey, wrappedKey)
	*pulWrappedKeyLen = C.CK_ULONG(len(wrappedKey))
	return fromError(nil)
}

//export goUnwrapKey
func goUnwrapKey(sessionHandle C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hUnwrappingKey C.CK_OBJECT_HANDLE, pWrappedKey C.CK_BYTE_PTR, ulWrappedKeyLen C.CK_ULONG, pTemplate C.CK_ATTRIBUTE_PTR, ulAttributeCount C.CK_ULONG, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	if pMechanism == nil || pWrappedKey == nil || phKey == nil || pTemplate == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goMechanism := toMechanism(pMechanism)
	goTemplate := toTemplate(pTemplate, ulAttributeCount)
	goUnwrappingKey := pkcs11.ObjectHandle(hUnwrappingKey)
	goWrappedKey := C.GoBytes(unsafe.Pointer(pWrappedKey), C.int(ulWrappedKeyLen))

	keyHandle, err := backend.UnwrapKey(goSessionHandle, []*pkcs11.Mechanism{goMechanism}, goUnwrappingKey, goWrappedKey, goTemplate)
	if err != nil {
		return fromError(nil)
	}

	*phKey = C.CK_OBJECT_HANDLE(keyHandle)
	return fromError(nil)
}

//export goDeriveKey
func goDeriveKey(sessionHandle C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hBaseKey C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulAttributeCount C.CK_ULONG, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	if pMechanism == nil || phKey == nil || pTemplate == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goMechanism := toMechanism(pMechanism)
	goTemplate := toTemplate(pTemplate, ulAttributeCount)
	goBaseKey := pkcs11.ObjectHandle(hBaseKey)

	keyHandle, err := backend.DeriveKey(goSessionHandle, []*pkcs11.Mechanism{goMechanism}, goBaseKey, goTemplate)
	if err != nil {
		return fromError(nil)
	}

	*phKey = C.CK_OBJECT_HANDLE(keyHandle)
	return fromError(nil)
}

//export goSeedRandom
func goSeedRandom(sessionHandle C.CK_SESSION_HANDLE, pSeed C.CK_BYTE_PTR, ulSeedLen C.CK_ULONG) C.CK_RV {
	if pSeed == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goSeed := C.GoBytes(unsafe.Pointer(pSeed), C.int(ulSeedLen))

	err := backend.SeedRandom(goSessionHandle, goSeed)
	return fromError(err)
}

//export goGenerateRandom
func goGenerateRandom(sessionHandle C.CK_SESSION_HANDLE, pRandomData C.CK_BYTE_PTR, ulRandomLen C.CK_ULONG) C.CK_RV {
	if pRandomData == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	goSessionHandle := pkcs11.SessionHandle(sessionHandle)
	goRandomData := (*[1 << 30]byte)(unsafe.Pointer(pRandomData))[:ulRandomLen:ulRandomLen]
	goRandomDataLen := int(ulRandomLen)

	randomData, err := backend.GenerateRandom(goSessionHandle, goRandomDataLen)
	if err != nil {
		return fromError(err)
	}

	copy(goRandomData, randomData)
	return fromError(nil)
}

//export goWaitForSlotEvent
func goWaitForSlotEvent(flags C.CK_FLAGS, pSlot C.CK_SLOT_ID_PTR, pReserved C.CK_VOID_PTR) C.CK_RV {
	if pSlot == nil || pReserved != nil {
		return C.CKR_ARGUMENTS_BAD
	}
	goFlags := uint(flags)

	slotEvent := <-backend.WaitForSlotEvent(goFlags)

	*pSlot = C.CK_SLOT_ID(slotEvent.SlotID)
	return fromError(nil)
}
