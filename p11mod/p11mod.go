// Copyright 2021 Namecoin Developers LGPLv3+

package p11mod

import (
	"log"
	"sync"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
	"github.com/namecoin/pkcs11mod"
)

var highBackend Backend
var highBackendError error

func SetBackend(b Backend, err error) {
	highBackend = b
	highBackendError = err
}

func init() {
	b := &llBackend{
		slots: []p11.Slot{},
		sessions: map[pkcs11.SessionHandle]*llSession{},
	}

	pkcs11mod.SetBackend(b)
}

type llSession struct {
	session p11.Session
	objects []p11.Object
	objectsPending []p11.Object
	signMechanism *pkcs11.Mechanism
	signKeyIndex int
	verifyMechanism *pkcs11.Mechanism
	verifyKeyIndex int
}

type llBackend struct {
	slots []p11.Slot
	slotsMutex sync.RWMutex
	sessions map[pkcs11.SessionHandle]*llSession
	sessionsMutex sync.RWMutex
}

func (ll *llBackend) Initialize() error {
	// Initialize() was already called by p11.OpenModule(), so there's
	// nothing to do here other than check the error value.
	if highBackendError != nil {
		return pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
	}

	return nil
}

func (ll *llBackend) Finalize() error {
	// p11 does not support Finalize().  Usually this is harmless though.
	return pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
}

func (ll *llBackend) GetInfo() (pkcs11.Info, error) {
	return highBackend.Info()
}

// Only call this when ll.slotsMutex is locked for writing.
func (ll *llBackend) updateSlots() error {
	slots, err := highBackend.Slots()
	if err != nil {
		return err
	}

	ll.slots = slots

	return nil
}

func (ll *llBackend) GetSlotList(tokenPresent bool) ([]uint, error) {
	ll.slotsMutex.Lock()
	defer ll.slotsMutex.Unlock()

	err := ll.updateSlots()
	if err != nil {
		return nil, err
	}

	slots := ll.slots

	ids := make([]uint, len(slots))
	for i, slot := range slots {
		ids[i] = slot.ID()
	}

	return ids, nil
}

func (ll *llBackend) getSlotByID(slotID uint) (p11.Slot, error) {
	// Fast path: if the ID is already known, we can use a read-only lock.

	ll.slotsMutex.RLock()

	for _, slot := range ll.slots {
		if slot.ID() == slotID {
			ll.slotsMutex.RUnlock()
			return slot, nil
		}
	}

	ll.slotsMutex.RUnlock()

	// Slow path: the ID isn't known, so we need a write lock.

	ll.slotsMutex.Lock()
	defer ll.slotsMutex.Unlock()

	ll.updateSlots()

	for _, slot := range ll.slots {
		if slot.ID() == slotID {
			return slot, nil
		}
	}

	return p11.Slot{}, pkcs11.Error(pkcs11.CKR_SLOT_ID_INVALID)
}

func (ll *llBackend) GetSlotInfo(slotID uint) (pkcs11.SlotInfo, error) {
	slot, err := ll.getSlotByID(slotID)
	if err != nil {
		return pkcs11.SlotInfo{}, err
	}

	return slot.Info()
}

func (ll *llBackend) GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error) {
	slot, err := ll.getSlotByID(slotID)
	if err != nil {
		return pkcs11.TokenInfo{}, err
	}

	return slot.TokenInfo()
}

func (ll *llBackend) GetMechanismList(slotID uint) ([]*pkcs11.Mechanism, error) {
	//slot, err := ll.getSlotByID(slotID)
	_, err := ll.getSlotByID(slotID)
	if err != nil {
		return []*pkcs11.Mechanism{}, err
	}

	// TODO
	log.Println("p11mod GetMechanismList: not implemented")
	return []*pkcs11.Mechanism{}, nil
}

func (ll *llBackend) GetMechanismInfo(slotID uint, m []*pkcs11.Mechanism) (pkcs11.MechanismInfo, error) {
	// TODO
	log.Println("p11mod GetMechanismInfo: not implemented")
	return pkcs11.MechanismInfo{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) InitPIN(sh pkcs11.SessionHandle, pin string) error {
	// TODO
	log.Println("p11mod InitPIN: not implemented")
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) SetPIN(sh pkcs11.SessionHandle, oldpin string, newpin string) error {
	// TODO
	log.Println("p11mod SetPIN: not implemented")
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

// Only call this when ll.sessionsMutex is locked for reading.
func (ll *llBackend) nextAvailableSessionHandle() pkcs11.SessionHandle {
	sessionHandle := pkcs11.SessionHandle(1)

	for {
		_, ok := ll.sessions[sessionHandle]
		if !ok {
			break
		}
		sessionHandle++
	}

	return sessionHandle
}

func (ll *llBackend) OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error) {
	slot, err := ll.getSlotByID(slotID)
	if err != nil {
		return 0, err
	}

	var session p11.Session

	if flags & pkcs11.CKF_RW_SESSION != 0 {
		session, err = slot.OpenWriteSession()
	} else {
		session, err = slot.OpenSession()
	}

	if err != nil {
		return 0, err
	}

	ll.sessionsMutex.Lock()
	defer ll.sessionsMutex.Unlock()

	sessionHandle := ll.nextAvailableSessionHandle()

	ll.sessions[sessionHandle] = &llSession{
		session: session,
		objects: []p11.Object{},
		objectsPending: []p11.Object{},
		signMechanism: nil,
		signKeyIndex: 0,
		verifyMechanism: nil,
		verifyKeyIndex: 0,
	}

	return sessionHandle, nil
}

func (ll *llBackend) getSessionByHandle(sh pkcs11.SessionHandle) (*llSession, error) {
	ll.sessionsMutex.RLock()
	defer ll.sessionsMutex.RUnlock()

	session, ok := ll.sessions[sh]
	if !ok {
		return nil, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	return session, nil
}

func (ll *llBackend) CloseSession(sh pkcs11.SessionHandle) error {
	session, err := ll.getSessionByHandle(sh)
	if err != nil {
		return err
	}

	err = session.session.Close()
	if err != nil {
		return err
	}

	ll.sessionsMutex.Lock()
	defer ll.sessionsMutex.Unlock()

	delete(ll.sessions, sh)

	return nil
}

func (ll *llBackend) CloseAllSessions(slotID uint) error {
	// TODO
	log.Println("p11mod CloseAllSessions: not implemented")
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) GetSessionInfo(sh pkcs11.SessionHandle) (pkcs11.SessionInfo, error) {
	// TODO
	log.Println("p11mod GetSessionInfo: not implemented")
	return pkcs11.SessionInfo{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) GetOperationState(sh pkcs11.SessionHandle) ([]byte, error) {
	// TODO
	log.Println("p11mod GetOperationState: not implemented")
	return []byte{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) SetOperationState(sh pkcs11.SessionHandle, state []byte, encryptKey, authKey pkcs11.ObjectHandle) error {
	// TODO
	log.Println("p11mod SetOperationState: not implemented")
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) Login(sh pkcs11.SessionHandle, userType uint, pin string) error {
	session, err := ll.getSessionByHandle(sh)
	if err != nil {
		return err
	}

	return session.session.LoginAs(userType, pin)
}

func (ll *llBackend) Logout(sh pkcs11.SessionHandle) error {
	// TODO
	log.Println("p11mod Logout: not implemented")
	return nil
}

func (ll *llBackend) CreateObject(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	session, err := ll.getSessionByHandle(sh)
	if err != nil {
		return 0, err
	}

	object, err := session.session.CreateObject(temp)
	if err != nil {
		return 0, err
	}

	session.objects = append(session.objects, object)

	// 0 is never a valid object handle, as per PKCS#11 spec.  So the object
	// handle of the final object is its index + 1, which is the same as the
	// length of the objects slice.
	resultHandle := len(session.objects)

	return pkcs11.ObjectHandle(resultHandle), nil
}

func (ll *llBackend) CopyObject(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, temp []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	// TODO
	log.Println("p11mod CopyObject: not implemented")
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) DestroyObject(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) error {
	session, err := ll.getSessionByHandle(sh)
	if err != nil {
		return err
	}

	// Handles are 1-indexed, while our slice is 0-indexed.
	objectIndex := int(oh-1)

	if objectIndex < 0 || objectIndex >= len(session.objects) {
		log.Printf("p11mod DestroyObject: object index invalid: requested %d, object count %d\n", objectIndex, len(session.objects))
		return pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
	}

	object := session.objects[objectIndex]

	return object.Destroy()
}

func (ll *llBackend) GetObjectSize(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) (uint, error) {
	// TODO
	log.Println("p11mod GetObjectSize: not implemented")
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) GetAttributeValue(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	session, err := ll.getSessionByHandle(sh)
	if err != nil {
		return []*pkcs11.Attribute{}, err
	}

	// Handles are 1-indexed, while our slice is 0-indexed.
	objectIndex := int(oh-1)

	if objectIndex < 0 || objectIndex >= len(session.objects) {
		log.Printf("p11mod GetAttributeValue: object index invalid: requested %d, object count %d\n", objectIndex, len(session.objects))
		return []*pkcs11.Attribute{}, pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
	}

	object := session.objects[objectIndex]

	result := make([]*pkcs11.Attribute, len(a))
	for i, t := range a {
		value, err := object.Attribute(t.Type)
		if err != nil && err.Error() != "attribute not found" && err.Error() != "too many attributes found" {
			return nil, err
		}
		if value == nil {
			// CKR_ATTRIBUTE_TYPE_INVALID, attribute not found, or too many attributes found
			value = []byte{}
		}

		result[i] = &pkcs11.Attribute{
			Type: t.Type,
			Value: value,
		}
	}

	return result, nil
}

func (ll *llBackend) SetAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, a []*pkcs11.Attribute) error {
	// TODO
	log.Println("p11mod SetAttributeValue: not implemented")
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) FindObjectsInit(sh pkcs11.SessionHandle, template []*pkcs11.Attribute) error {
	session, err := ll.getSessionByHandle(sh)
	if err != nil {
		return err
	}

	objects, err := session.session.FindObjects(template)
	if err != nil {
		if err == pkcs11.Error(pkcs11.CKR_OPERATION_NOT_INITIALIZED) {
			// session.FindObjects() can relay CKR_OPERATION_NOT_INITIALIZED from
			// FindObjects or FindObjectsFinal, but PKCS#11 spec says
			// FindObjectsInit cannot return CKR_OPERATION_NOT_INITIALIZED.  So we
			// have to return a different error.
			return pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
		} else if err.Error() == "no objects found" {
			objects = []p11.Object{}
		} else {
			return err
		}
	}

	session.objects = append(session.objects, objects...)
	session.objectsPending = objects

	return nil
}

func (ll *llBackend) FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	session, err := ll.getSessionByHandle(sh)
	if err != nil {
		return []pkcs11.ObjectHandle{}, false, err
	}

	// 0 is never a valid object handle, as per PKCS#11 spec.  So if all
	// objects are still pending, this returns 1.
	resultHandle := len(session.objects) - len(session.objectsPending) + 1

	numResults := len(session.objectsPending)
	if numResults > max {
		numResults = max
	}

	results := make([]pkcs11.ObjectHandle, numResults)
	for i, _ := range results {
		results[i] = pkcs11.ObjectHandle(resultHandle)
		resultHandle++
	}

	session.objectsPending = session.objectsPending[numResults:]

	return results, false, nil
}

func (ll *llBackend) FindObjectsFinal(sh pkcs11.SessionHandle) error {
	_, err := ll.getSessionByHandle(sh)
	if err != nil {
		return err
	}

	return nil
}

func (ll *llBackend) EncryptInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error {
	// TODO
	log.Println("p11mod EncryptInit: not implemented")
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) Encrypt(sh pkcs11.SessionHandle, message []byte) ([]byte, error) {
	// TODO
	log.Println("p11mod Encrypt: not implemented")
	return []byte{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) EncryptUpdate(sh pkcs11.SessionHandle, plain []byte) ([]byte, error) {
	// TODO
	log.Println("p11mod EncryptUpdate: not implemented")
	return []byte{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) EncryptFinal(sh pkcs11.SessionHandle) ([]byte, error) {
	// TODO
	log.Println("p11mod EncryptFinal: not implemented")
	return []byte{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) DecryptInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error {
	// TODO
	log.Println("p11mod DecryptInit: not implemented")
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) Decrypt(sh pkcs11.SessionHandle, cipher []byte) ([]byte, error) {
	// TODO
	log.Println("p11mod Decrypt: not implemented")
	return []byte{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) DecryptUpdate(sh pkcs11.SessionHandle, cipher []byte) ([]byte, error) {
	// TODO
	log.Println("p11mod DecryptUpdate: not implemented")
	return []byte{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) DecryptFinal(sh pkcs11.SessionHandle) ([]byte, error) {
	// TODO
	log.Println("p11mod DecryptFinal: not implemented")
	return []byte{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) DigestInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism) error {
	// TODO
	log.Println("p11mod DigestInit: not implemented")
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) Digest(sh pkcs11.SessionHandle, message []byte) ([]byte, error) {
	// TODO
	log.Println("p11mod Digest: not implemented")
	return []byte{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) DigestUpdate(sh pkcs11.SessionHandle, message []byte) error {
	// TODO
	log.Println("p11mod DigestUpdate: not implemented")
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) DigestKey(sh pkcs11.SessionHandle, key pkcs11.ObjectHandle) error {
	// TODO
	log.Println("p11mod DigestKey: not implemented")
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) DigestFinal(sh pkcs11.SessionHandle) ([]byte, error) {
	// TODO
	log.Println("p11mod DigestFinal: not implemented")
	return []byte{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) SignInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error {
	session, err := ll.getSessionByHandle(sh)
	if err != nil {
		return err
	}

	// Handles are 1-indexed, while our slice is 0-indexed.
	objectIndex := int(o-1)

	if objectIndex < 0 || objectIndex >= len(session.objects) {
		log.Printf("p11mod SignInit: key index invalid: requested %d, object count %d\n", objectIndex, len(session.objects))
		return pkcs11.Error(pkcs11.CKR_KEY_HANDLE_INVALID)
	}

	if len(m) != 1 {
		log.Println("p11mod SignInit: expected exactly one mechanism")
		return pkcs11.Error(pkcs11.CKR_MECHANISM_INVALID)
	}

	if m[0] == nil {
		log.Println("p11mod SignInit: nil mechanism")
		return pkcs11.Error(pkcs11.CKR_MECHANISM_INVALID)
	}

	session.signMechanism = m[0]
	session.signKeyIndex = objectIndex

	return nil
}

func (ll *llBackend) Sign(sh pkcs11.SessionHandle, message []byte) ([]byte, error) {
	session, err := ll.getSessionByHandle(sh)
	if err != nil {
		return nil, err
	}

	if session.signMechanism == nil {
		return nil, pkcs11.Error(pkcs11.CKR_OPERATION_NOT_INITIALIZED)
	}

	// Inactivate the signature operation regardless of whether Sign errors.
	defer func() {
		session.signMechanism = nil
		session.signKeyIndex = 0
	}()

	priv := p11.PrivateKey(session.objects[session.signKeyIndex])

	signature, err := priv.Sign(*session.signMechanism, message)
	if err != nil {
		if err == pkcs11.Error(pkcs11.CKR_KEY_FUNCTION_NOT_PERMITTED) || err == pkcs11.Error(pkcs11.CKR_KEY_HANDLE_INVALID) || err == pkcs11.Error(pkcs11.CKR_KEY_SIZE_RANGE) || err == pkcs11.Error(pkcs11.CKR_KEY_TYPE_INCONSISTENT) || err == pkcs11.Error(pkcs11.CKR_MECHANISM_INVALID) || err == pkcs11.Error(pkcs11.CKR_MECHANISM_PARAM_INVALID) || err == pkcs11.Error(pkcs11.CKR_OPERATION_ACTIVE) || err == pkcs11.Error(pkcs11.CKR_PIN_EXPIRED) {
			// priv.Sign() can relay these error values from SignInit, but
			// PKCS#11 spec says Sign cannot return these.  So we have to
			// return a different error.
			return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
		} else {
			return nil, err
		}
	}

	return signature, nil
}

func (ll *llBackend) SignUpdate(sh pkcs11.SessionHandle, message []byte) error {
	// TODO
	log.Println("p11mod SignUpdate: not implemented")
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) SignFinal(sh pkcs11.SessionHandle) ([]byte, error) {
	// TODO
	log.Println("p11mod SignFinal: not implemented")
	return []byte{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) SignRecoverInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, key pkcs11.ObjectHandle) error {
	// TODO
	log.Println("p11mod SignRecoverInit: not implemented")
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) SignRecover(sh pkcs11.SessionHandle, data []byte) ([]byte, error) {
	// TODO
	log.Println("p11mod SignRecover: not implemented")
	return []byte{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) VerifyInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, key pkcs11.ObjectHandle) error {
	session, err := ll.getSessionByHandle(sh)
	if err != nil {
		return err
	}

	// Handles are 1-indexed, while our slice is 0-indexed.
	objectIndex := int(key-1)

	if objectIndex < 0 || objectIndex >= len(session.objects) {
		log.Printf("p11mod VerifyInit: key index invalid: requested %d, object count %d\n", objectIndex, len(session.objects))
		return pkcs11.Error(pkcs11.CKR_KEY_HANDLE_INVALID)
	}

	if len(m) != 1 {
		log.Println("p11mod VerifyInit: expected exactly one mechanism")
		return pkcs11.Error(pkcs11.CKR_MECHANISM_INVALID)
	}

	if m[0] == nil {
		log.Println("p11mod VerifyInit: nil mechanism")
		return pkcs11.Error(pkcs11.CKR_MECHANISM_INVALID)
	}

	session.verifyMechanism = m[0]
	session.verifyKeyIndex = objectIndex

	return nil
}

func (ll *llBackend) Verify(sh pkcs11.SessionHandle, data []byte, signature []byte) error {
	session, err := ll.getSessionByHandle(sh)
	if err != nil {
		return err
	}

	if session.verifyMechanism == nil {
		return pkcs11.Error(pkcs11.CKR_OPERATION_NOT_INITIALIZED)
	}

	// Inactivate the verification operation regardless of whether Verify errors.
	defer func() {
		session.verifyMechanism = nil
		session.verifyKeyIndex = 0
	}()

	pub := p11.PublicKey(session.objects[session.verifyKeyIndex])

	err = pub.Verify(*session.verifyMechanism, data, signature)
	if err != nil {
		if err == pkcs11.Error(pkcs11.CKR_KEY_FUNCTION_NOT_PERMITTED) || err == pkcs11.Error(pkcs11.CKR_KEY_HANDLE_INVALID) || err == pkcs11.Error(pkcs11.CKR_KEY_SIZE_RANGE) || err == pkcs11.Error(pkcs11.CKR_KEY_TYPE_INCONSISTENT) || err == pkcs11.Error(pkcs11.CKR_MECHANISM_INVALID) || err == pkcs11.Error(pkcs11.CKR_MECHANISM_PARAM_INVALID) || err == pkcs11.Error(pkcs11.CKR_OPERATION_ACTIVE) || err == pkcs11.Error(pkcs11.CKR_PIN_EXPIRED) || err == pkcs11.Error(pkcs11.CKR_USER_NOT_LOGGED_IN) {
			// pub.Verify() can relay these error values from VerifyInit, but
			// PKCS#11 spec says Verify cannot return these.  So we have to
			// return a different error.
			return pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
		} else {
			return err
		}
	}

	return nil
}

func (ll *llBackend) VerifyUpdate(sh pkcs11.SessionHandle, part []byte) error {
	// TODO
	log.Println("p11mod VerifyUpdate: not implemented")
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) VerifyFinal(sh pkcs11.SessionHandle, signature []byte) error {
	// TODO
	log.Println("p11mod VerifyFinal: not implemented")
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) VerifyRecoverInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, key pkcs11.ObjectHandle) error {
	// TODO
	log.Println("p11mod VerifyRecoverInit: not implemented")
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) VerifyRecover(sh pkcs11.SessionHandle, signature []byte) ([]byte, error) {
	// TODO
	log.Println("p11mod VerifyRecover: not implemented")
	return []byte{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) DigestEncryptUpdate(sh pkcs11.SessionHandle, part []byte) ([]byte, error) {
	// TODO
	log.Println("p11mod DigestEncryptUpdate: not implemented")
	return []byte{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) DecryptDigestUpdate(sh pkcs11.SessionHandle, cipher []byte) ([]byte, error) {
	// TODO
	log.Println("p11mod DecryptDigestUpdate: not implemented")
	return []byte{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) SignEncryptUpdate(sh pkcs11.SessionHandle, part []byte) ([]byte, error) {
	// TODO
	log.Println("p11mod SignEncryptUpdate: not implemented")
	return []byte{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) DecryptVerifyUpdate(sh pkcs11.SessionHandle, cipher []byte) ([]byte, error) {
	// TODO
	log.Println("p11mod DecryptVerifyUpdate: not implemented")
	return []byte{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) GenerateKey(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, temp []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	// TODO
	log.Println("p11mod GenerateKey: not implemented")
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) GenerateKeyPair(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, public, private []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	// TODO
	log.Println("p11mod GenerateKeyPair: not implemented")
	return 0, 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) WrapKey(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, wrappingkey, key pkcs11.ObjectHandle) ([]byte, error) {
	// TODO
	log.Println("p11mod WrapKey: not implemented")
	return []byte{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) UnwrapKey(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, unwrappingkey pkcs11.ObjectHandle, wrappedkey []byte, a []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	// TODO
	log.Println("p11mod UnwrapKey: not implemented")
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) DeriveKey(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, basekey pkcs11.ObjectHandle, a []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	// TODO
	log.Println("p11mod DeriveKey: not implemented")
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) SeedRandom(sh pkcs11.SessionHandle, seed []byte) error {
	// TODO
	log.Println("p11mod SeedRandom: not implemented")
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) GenerateRandom(sh pkcs11.SessionHandle, length int) ([]byte, error) {
	// TODO
	log.Println("p11mod GenerateRandom: not implemented")
	return []byte{}, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (ll *llBackend) WaitForSlotEvent(flags uint) chan pkcs11.SlotEvent {
	sl := make(chan pkcs11.SlotEvent, 1)
	// TODO
	log.Println("p11mod WaitForSlotEvent: not implemented")
	return sl
}
