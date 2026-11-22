//go:build darwin && cgo

package endpointservice

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -framework Foundation -framework CoreWLAN -framework LocalAuthentication
#include <stdlib.h>
#include <Security/Security.h>
int sohaEAPIdentityPresent(const unsigned char *der, unsigned long size);
int sohaEAPAssociate(const char *name, const char *ssid, const char *username, int security, const unsigned char *der, unsigned long size);
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"unsafe"
)

func darwinEAPIdentityReadback(ctx context.Context, der []byte) error {
	status, err := darwinEAPIdentityStatus(ctx, der)
	if err != nil {
		return err
	}
	if status != 0 {
		return fmt.Errorf("installed system EAP private identity is unavailable (status %d)", status)
	}
	return nil
}

func darwinEAPIdentityRetired(ctx context.Context, der []byte) error {
	status, err := darwinEAPIdentityStatus(ctx, der)
	if err != nil {
		return err
	}
	if status == int(C.errSecItemNotFound) {
		return nil
	}
	if status == 0 {
		return errors.New("retired Soha EAP identity remains installed in System Keychain")
	}
	return fmt.Errorf("retired EAP identity removal cannot be verified (status %d)", status)
}

func darwinEAPIdentityStatus(ctx context.Context, der []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(der) == 0 || len(der) > 16384 {
		return 0, errors.New("EAP identity certificate is invalid")
	}
	result := C.sohaEAPIdentityPresent((*C.uchar)(unsafe.Pointer(&der[0])), C.ulong(len(der)))
	return int(result), ctx.Err()
}

func darwinEAPAssociate(ctx context.Context, name, ssid, username, security string, der []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(der) == 0 || len(der) > 16384 {
		return errors.New("EAP identity certificate is invalid")
	}
	interfaceName, networkName, identity := C.CString(name), C.CString(ssid), C.CString(username)
	defer C.free(unsafe.Pointer(interfaceName))
	defer C.free(unsafe.Pointer(networkName))
	defer C.free(unsafe.Pointer(identity))
	// CoreWLAN association is synchronous; its return is an OS result, not NAS authorization.
	securityMode := C.int(2)
	if security == "wpa3-enterprise" {
		securityMode = 3
	}
	if result := C.sohaEAPAssociate(interfaceName, networkName, identity, securityMode, (*C.uchar)(unsafe.Pointer(&der[0])), C.ulong(len(der))); result != 0 {
		return fmt.Errorf("macOS EAP association failed (status %d); check Wi-Fi and Location Services", int(result))
	}
	return ctx.Err()
}
