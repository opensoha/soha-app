//go:build windows

package endpointservice

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	eapCertSetProperty = windows.NewLazySystemDLL("crypt32.dll").NewProc("CertSetCertificateContextProperty")
	eapCertGetProperty = windows.NewLazySystemDLL("crypt32.dll").NewProc("CertGetCertificateContextProperty")
)

const eapCertificateOwnerProperty = 0x8001

func uint32Error(err error) uint32 {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return uint32(errno)
	}
	return 0
}

type eapKeyProviderInfo struct {
	ContainerName  *uint16
	ProviderName   *uint16
	ProviderType   uint32
	Flags          uint32
	ParameterCount uint32
	Parameters     unsafe.Pointer
	KeySpec        uint32
}

func openEAPUserStore(name string) (windows.Handle, error) {
	if name != "MY" && name != "CA" && name != "ROOT" {
		return 0, errors.New("EAP certificate store is invalid")
	}
	return windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM_W, 0, 0, windows.CERT_SYSTEM_STORE_CURRENT_USER|windows.CERT_STORE_OPEN_EXISTING_FLAG, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))))
}

func addEAPUserCertificate(storeName string, certificate *x509.Certificate, key *eapCNGKey, deviceID string) error {
	if len(certificate.Raw) == 0 || len(certificate.Raw) > 16384 {
		return errors.New("EAP certificate has an invalid size")
	}
	store, err := openEAPUserStore(storeName)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	context, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, &certificate.Raw[0], uint32(len(certificate.Raw)))
	if err != nil {
		return err
	}
	defer windows.CertFreeCertificateContext(context)
	if !identifierPattern.MatchString(deviceID) {
		return errors.New("EAP certificate owner is invalid")
	}
	owner := []byte("OpenSoha.EAP/" + deviceID)
	property := windows.CryptDataBlob{Size: uint32(len(owner)), Data: &owner[0]}
	if err := eapCertSetProperty.Find(); err != nil {
		return err
	}
	if result, _, callErr := eapCertSetProperty.Call(uintptr(unsafe.Pointer(context)), eapCertificateOwnerProperty, 0, uintptr(unsafe.Pointer(&property))); result == 0 {
		return fmt.Errorf("mark owned EAP certificate: %w", callErr)
	}
	if key != nil {
		public, ok := certificate.PublicKey.(*ecdsa.PublicKey)
		if !ok || !key.public.Equal(public) || storeName != "MY" {
			return errors.New("EAP certificate does not match its CNG private key")
		}
		info := eapKeyProviderInfo{ContainerName: windows.StringToUTF16Ptr(key.name), ProviderName: windows.StringToUTF16Ptr(eapCNGProvider), KeySpec: windows.CERT_NCRYPT_KEY_SPEC}
		if err := eapCertSetProperty.Find(); err != nil {
			return err
		}
		result, _, callErr := eapCertSetProperty.Call(uintptr(unsafe.Pointer(context)), 2, 0, uintptr(unsafe.Pointer(&info)))
		if result == 0 {
			return fmt.Errorf("associate EAP certificate with CNG key: %w", callErr)
		}
	}
	if key != nil {
		return windows.CertAddCertificateContextToStore(store, context, windows.CERT_STORE_ADD_REPLACE_EXISTING, nil)
	}
	err = windows.CertAddCertificateContextToStore(store, context, windows.CERT_STORE_ADD_NEW, nil)
	if err != nil && uint32Error(err) == uint32(windows.CRYPT_E_EXISTS) {
		digest := sha1.Sum(certificate.Raw)
		query := windows.CryptHashBlob{Size: uint32(len(digest)), Data: &digest[0]}
		existing, findErr := windows.CertFindCertificateInStore(store, windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0, windows.CERT_FIND_SHA1_HASH, unsafe.Pointer(&query), nil)
		if findErr != nil {
			return findErr
		}
		defer windows.CertFreeCertificateContext(existing)
		if existing.Length == uint32(len(certificate.Raw)) && bytes.Equal(unsafe.Slice(existing.EncodedCert, existing.Length), certificate.Raw) {
			return nil
		}
	}
	return err
}

func removeOwnedEAPUserCertificate(storeName string, certificate *x509.Certificate, deviceID string) error {
	store, err := openEAPUserStore(storeName)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	digest := sha1.Sum(certificate.Raw)
	query := windows.CryptHashBlob{Size: uint32(len(digest)), Data: &digest[0]}
	context, err := windows.CertFindCertificateInStore(store, windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0, windows.CERT_FIND_SHA1_HASH, unsafe.Pointer(&query), nil)
	if err != nil && uint32Error(err) == uint32(windows.CRYPT_E_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	if context.Length != uint32(len(certificate.Raw)) || !bytes.Equal(unsafe.Slice(context.EncodedCert, context.Length), certificate.Raw) {
		_ = windows.CertFreeCertificateContext(context)
		return errors.New("obsolete EAP certificate differs from the managed certificate")
	}
	if err := eapCertGetProperty.Find(); err != nil {
		_ = windows.CertFreeCertificateContext(context)
		return err
	}
	owner := make([]byte, 256)
	size := uint32(len(owner))
	result, _, _ := eapCertGetProperty.Call(uintptr(unsafe.Pointer(context)), eapCertificateOwnerProperty, uintptr(unsafe.Pointer(&owner[0])), uintptr(unsafe.Pointer(&size)))
	if result == 0 || size > uint32(len(owner)) || !bytes.Equal(owner[:size], []byte("OpenSoha.EAP/"+deviceID)) {
		_ = windows.CertFreeCertificateContext(context)
		return nil
	}
	// Delete consumes the context, including when Windows reports a deletion error.
	return windows.CertDeleteCertificateFromStore(context)
}

func readbackEAPUserCertificate(certificate *x509.Certificate) error {
	store, err := openEAPUserStore("MY")
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	// SHA-1 is the Windows store selector; the returned DER must still match exactly.
	digest := sha1.Sum(certificate.Raw)
	query := windows.CryptHashBlob{Size: uint32(len(digest)), Data: &digest[0]}
	context, err := windows.CertFindCertificateInStore(store, windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0, windows.CERT_FIND_SHA1_HASH, unsafe.Pointer(&query), nil)
	if err != nil {
		return err
	}
	defer windows.CertFreeCertificateContext(context)
	if context.Length == 0 || context.Length > 16384 || !bytes.Equal(unsafe.Slice(context.EncodedCert, context.Length), certificate.Raw) {
		return errors.New("installed EAP certificate differs from the requested certificate")
	}
	var handle windows.Handle
	var keySpec uint32
	var callerFree bool
	if err := windows.CryptAcquireCertificatePrivateKey(context, windows.CRYPT_ACQUIRE_SILENT_FLAG|windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG|windows.CRYPT_ACQUIRE_COMPARE_KEY_FLAG, nil, &handle, &keySpec, &callerFree); err != nil {
		return err
	}
	if callerFree {
		defer callEAPCNG(eapNCryptFree, uintptr(handle))
	}
	if keySpec != windows.CERT_NCRYPT_KEY_SPEC {
		return errors.New("installed EAP identity does not use CNG")
	}
	key := &eapCNGKey{key: uintptr(handle)}
	policy, err := key.property("Export Policy")
	if err != nil || len(policy) != 4 || policy[0] != 0 || policy[1] != 0 || policy[2] != 0 || policy[3] != 0 {
		return errors.New("installed EAP private key is exportable")
	}
	raw, err := key.exportPublic()
	if err != nil {
		return err
	}
	key.public, err = parseEAPP256Blob(raw)
	public, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if err != nil || !ok || !key.public.Equal(public) {
		return errors.New("installed CNG key does not match the EAP certificate")
	}
	digest256 := sha256.Sum256(append([]byte("OpenSoha EAP private-key readback\x00"), certificate.Raw...))
	signature, err := key.Sign(nil, digest256[:], crypto.SHA256)
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(public, digest256[:], signature) {
		return errors.New("installed EAP private-key signature is invalid")
	}
	return nil
}

func readbackEAPPublicCertificate(storeName string, certificate *x509.Certificate) error {
	store, err := openEAPUserStore(storeName)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	digest := sha1.Sum(certificate.Raw)
	query := windows.CryptHashBlob{Size: uint32(len(digest)), Data: &digest[0]}
	context, err := windows.CertFindCertificateInStore(store, windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0, windows.CERT_FIND_SHA1_HASH, unsafe.Pointer(&query), nil)
	if err != nil {
		return err
	}
	defer windows.CertFreeCertificateContext(context)
	if context.Length != uint32(len(certificate.Raw)) || !bytes.Equal(unsafe.Slice(context.EncodedCert, context.Length), certificate.Raw) {
		return errors.New("Windows EAP trust certificate differs from the expected certificate")
	}
	return nil
}
