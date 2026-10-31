//go:build windows

package endpointservice

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	eapNCrypt             = windows.NewLazySystemDLL("ncrypt.dll")
	eapNCryptOpenProvider = eapNCrypt.NewProc("NCryptOpenStorageProvider")
	eapNCryptOpenKey      = eapNCrypt.NewProc("NCryptOpenKey")
	eapNCryptCreateKey    = eapNCrypt.NewProc("NCryptCreatePersistedKey")
	eapNCryptSetProperty  = eapNCrypt.NewProc("NCryptSetProperty")
	eapNCryptGetProperty  = eapNCrypt.NewProc("NCryptGetProperty")
	eapNCryptFinalizeKey  = eapNCrypt.NewProc("NCryptFinalizeKey")
	eapNCryptExportKey    = eapNCrypt.NewProc("NCryptExportKey")
	eapNCryptSignHash     = eapNCrypt.NewProc("NCryptSignHash")
	eapNCryptFree         = eapNCrypt.NewProc("NCryptFreeObject")
	eapNCryptDelete       = eapNCrypt.NewProc("NCryptDeleteKey")
)

const eapCNGProvider = "Microsoft Software Key Storage Provider"

type eapCNGStatus uint32

func (status eapCNGStatus) Error() string {
	return fmt.Sprintf("native CNG EAP operation failed (status 0x%08x)", uint32(status))
}

type eapCNGKey struct {
	provider uintptr
	key      uintptr
	name     string
	public   *ecdsa.PublicKey
}

func callEAPCNG(procedure *windows.LazyProc, arguments ...uintptr) error {
	if err := procedure.Find(); err != nil {
		return err
	}
	result, _, _ := procedure.Call(arguments...)
	if uint32(result) != 0 {
		return eapCNGStatus(result)
	}
	return nil
}

func openEAPCNGKey(deviceID, requestID string, create bool) (*eapCNGKey, error) {
	if !identifierPattern.MatchString(deviceID) || !identifierPattern.MatchString(requestID) {
		return nil, errors.New("CNG EAP identity reference is invalid")
	}
	key := &eapCNGKey{name: "OpenSoha.EAP." + eapPayloadUUID(deviceID+"/"+requestID)}
	if err := callEAPCNG(eapNCryptOpenProvider, uintptr(unsafe.Pointer(&key.provider)), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(eapCNGProvider))), 0); err != nil {
		return nil, err
	}
	err := callEAPCNG(eapNCryptOpenKey, key.provider, uintptr(unsafe.Pointer(&key.key)), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(key.name))), 0, 0x40)
	if create && (err == eapCNGStatus(0x80090016) || err == eapCNGStatus(0x80090011)) {
		err = callEAPCNG(eapNCryptCreateKey, key.provider, uintptr(unsafe.Pointer(&key.key)), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("ECDSA_P256"))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(key.name))), 0, 0)
		if err == nil {
			zero := uint32(0)
			err = callEAPCNG(eapNCryptSetProperty, key.key, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("Export Policy"))), uintptr(unsafe.Pointer(&zero)), 4, 0x80000000)
		}
		if err == nil {
			err = callEAPCNG(eapNCryptFinalizeKey, key.key, 0x40)
		}
	}
	if err != nil {
		key.Close()
		return nil, err
	}
	policy, err := key.property("Export Policy")
	if err != nil || len(policy) != 4 || binary.LittleEndian.Uint32(policy) != 0 {
		key.Close()
		return nil, errors.New("CNG EAP key permits private-key export or has no export policy")
	}
	raw, err := key.exportPublic()
	if err != nil {
		key.Close()
		return nil, err
	}
	key.public, err = parseEAPP256Blob(raw)
	if err != nil {
		key.Close()
		return nil, err
	}
	return key, nil
}

func (key *eapCNGKey) Close() {
	if key.key != 0 {
		_ = callEAPCNG(eapNCryptFree, key.key)
		key.key = 0
	}
	if key.provider != 0 {
		_ = callEAPCNG(eapNCryptFree, key.provider)
		key.provider = 0
	}
}

func (key *eapCNGKey) property(name string) ([]byte, error) {
	raw := make([]byte, 4096)
	var size uint32
	err := callEAPCNG(eapNCryptGetProperty, key.key, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), uintptr(unsafe.Pointer(&raw[0])), uintptr(len(raw)), uintptr(unsafe.Pointer(&size)), 0x40)
	if err != nil {
		return nil, err
	}
	if size > uint32(len(raw)) {
		return nil, errors.New("CNG EAP property exceeds the safe size")
	}
	return raw[:size], nil
}

func (key *eapCNGKey) exportPublic() ([]byte, error) {
	raw := make([]byte, 1024)
	var size uint32
	err := callEAPCNG(eapNCryptExportKey, key.key, 0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("ECCPUBLICBLOB"))), 0, uintptr(unsafe.Pointer(&raw[0])), uintptr(len(raw)), uintptr(unsafe.Pointer(&size)), 0)
	if err != nil {
		return nil, err
	}
	if size > uint32(len(raw)) {
		return nil, errors.New("CNG EAP public key exceeds the safe size")
	}
	return raw[:size], nil
}

func (key *eapCNGKey) Public() crypto.PublicKey { return key.public }

func (key *eapCNGKey) Sign(_ io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	if options == nil || options.HashFunc() != crypto.SHA256 || len(digest) != 32 {
		return nil, errors.New("CNG EAP CSR requires SHA-256")
	}
	raw := make([]byte, 64)
	var size uint32
	err := callEAPCNG(eapNCryptSignHash, key.key, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)), uintptr(unsafe.Pointer(&raw[0])), uintptr(len(raw)), uintptr(unsafe.Pointer(&size)), 0x40)
	if err != nil {
		return nil, err
	}
	if size != uint32(len(raw)) {
		return nil, errors.New("CNG EAP signature has an unexpected length")
	}
	return encodeEAPCNGSignature(raw)
}
