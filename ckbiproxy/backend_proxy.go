// Copyright 2018 Namecoin Developers LGPLv3+

package main

import (
	"log"

	"github.com/miekg/pkcs11"
)

type BackendProxy struct {
}

var realBackend *pkcs11.Ctx

func init() {
	realBackend = pkcs11.New("/usr/lib64/libnssckbi.so")
}

func (b BackendProxy) Initialize() error {
	log.Println("Proxy pkcs11 backend initialized")
	return realBackend.Initialize()
}

func (b BackendProxy) Finalize() error {
	log.Println("Proxy pkcs11 backend closing")
	return realBackend.Finalize()
}

func (b BackendProxy) GetInfo() (pkcs11.Info, error) {
	log.Println("Proxy pkcs11 backend GetInfo")
	return realBackend.GetInfo()
}

func (b BackendProxy) GetSlotList(tokenPresent bool) ([]uint, error) {
	slotList, err := realBackend.GetSlotList(tokenPresent)
	log.Printf("Proxy pkcs11 backend GetSlotList: result is %v\n", slotList)
	return slotList, err
}

func (b BackendProxy) GetSlotInfo(slotID uint) (pkcs11.SlotInfo, error) {
	slotInfo, err := realBackend.GetSlotInfo(slotID)
	log.Printf("Proxy pkcs11 backend GetSlotInfo: result is %v\n", slotInfo)
	return slotInfo, err
}

func (b BackendProxy) GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error) {
	tokenInfo, err := realBackend.GetTokenInfo(slotID)
	log.Printf("Proxy pkcs11 backend GetTokenInfo: result is %v\n", tokenInfo)
	return tokenInfo, err
}

func (b BackendProxy) OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error) {
	sessionHandle, err := realBackend.OpenSession(slotID, flags)
	log.Printf("Proxy pkcs11 backend OpenSession: result is %v\n", sessionHandle)
	return sessionHandle, err
}

func (b BackendProxy) Login(sh pkcs11.SessionHandle, userType uint, pin string) error {
	err := realBackend.Login(sh, userType, pin)
	log.Printf("Proxy pkcs11 backend Login\n")
	return err
}

func (b BackendProxy) FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error {
	err := realBackend.FindObjectsInit(sh, temp)
	log.Printf("Proxy pkcs11 backend FindObjectsInit\n")
	return err
}
