//go:build darwin && cgo

package endpointservice

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -framework Foundation -framework CoreWLAN -framework LocalAuthentication
#include <stdlib.h>
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
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(der) == 0 || len(der) > 16384 {
		return errors.New("EAP identity certificate is invalid")
	}
	if result := C.sohaEAPIdentityPresent((*C.uchar)(unsafe.Pointer(&der[0])), C.ulong(len(der))); result != 0 {
		return fmt.Errorf("installed system EAP private identity is unavailable (status %d)", int(result))
	}
	return ctx.Err()
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
