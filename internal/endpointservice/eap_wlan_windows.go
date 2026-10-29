//go:build windows

package endpointservice

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	eapWlanDLL        = windows.NewLazySystemDLL("wlanapi.dll")
	eapWlanOpen       = eapWlanDLL.NewProc("WlanOpenHandle")
	eapWlanClose      = eapWlanDLL.NewProc("WlanCloseHandle")
	eapWlanFree       = eapWlanDLL.NewProc("WlanFreeMemory")
	eapWlanGet        = eapWlanDLL.NewProc("WlanGetProfile")
	eapWlanSet        = eapWlanDLL.NewProc("WlanSetProfile")
	eapWlanSetUser    = eapWlanDLL.NewProc("WlanSetProfileEapXmlUserData")
	eapWlanDelete     = eapWlanDLL.NewProc("WlanDeleteProfile")
	eapWlanConnect    = eapWlanDLL.NewProc("WlanConnect")
	eapWlanQuery      = eapWlanDLL.NewProc("WlanQueryInterface")
	eapWlanDisconnect = eapWlanDLL.NewProc("WlanDisconnect")
)

type eapWlanClient struct {
	handle uintptr
	guid   windows.GUID
}

func callEAPWlan(procedure *windows.LazyProc, arguments ...uintptr) error {
	if err := procedure.Find(); err != nil {
		return err
	}
	code, _, _ := procedure.Call(arguments...)
	if code != 0 {
		return fmt.Errorf("%s: %w", procedure.Name, windows.Errno(code))
	}
	return nil
}

func openEAPWlan(adapter EAPAdapter) (*eapWlanClient, error) {
	guid, err := windows.GUIDFromString(adapter.ID)
	if err != nil || adapter.Medium != "wifi" {
		return nil, errors.New("EAP wireless interface is invalid")
	}
	client := &eapWlanClient{guid: guid}
	var version uint32
	if err := callEAPWlan(eapWlanOpen, 2, 0, uintptr(unsafe.Pointer(&version)), uintptr(unsafe.Pointer(&client.handle))); err != nil {
		return nil, err
	}
	return client, nil
}

func (client *eapWlanClient) Close() {
	_ = callEAPWlan(eapWlanClose, client.handle, 0)
}

func (client *eapWlanClient) get(name string) ([]byte, bool, error) {
	var output *uint16
	var flags, access uint32
	err := callEAPWlan(eapWlanGet, client.handle, uintptr(unsafe.Pointer(&client.guid)), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), 0, uintptr(unsafe.Pointer(&output)), uintptr(unsafe.Pointer(&flags)), uintptr(unsafe.Pointer(&access)))
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer eapWlanFree.Call(uintptr(unsafe.Pointer(output)))
	if flags&1 != 0 || flags&2 == 0 || output == nil {
		return nil, false, errors.New("EAP will not change a group policy or all-user wireless profile")
	}
	for length := 0; length < 65536; length++ {
		if *(*uint16)(unsafe.Add(unsafe.Pointer(output), length*2)) == 0 {
			return []byte(windows.UTF16ToString(unsafe.Slice(output, length))), true, nil
		}
	}
	return nil, false, errors.New("Windows EAP wireless profile exceeds the safe size")
}

func (client *eapWlanClient) set(profile eapWindowsProfile, expected []byte) error {
	actual, present, err := client.get(profile.Name)
	if err != nil {
		return err
	}
	var overwrite uintptr
	if present {
		if len(expected) == 0 || matchEAPWindowsXML(actual, expected) != nil {
			return errors.New("existing wireless profile is not the managed configuration")
		}
		overwrite = 1
	}
	var reason uint32
	if err := callEAPWlan(eapWlanSet, client.handle, uintptr(unsafe.Pointer(&client.guid)), 2, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(string(profile.XML)))), 0, overwrite, 0, uintptr(unsafe.Pointer(&reason))); err != nil {
		return fmt.Errorf("EAP wireless profile rejected (reason %d): %w", reason, err)
	}
	return client.readback(profile)
}

func (client *eapWlanClient) readback(profile eapWindowsProfile) error {
	actual, present, err := client.get(profile.Name)
	if err != nil {
		return err
	}
	if !present {
		return errors.New("managed EAP wireless profile is missing")
	}
	if err := matchEAPWindowsXML(actual, profile.XML); err != nil {
		return err
	}
	// Windows has no EAP XML user-data getter; acknowledge a fresh, exact write.
	return callEAPWlan(eapWlanSetUser, client.handle, uintptr(unsafe.Pointer(&client.guid)), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(profile.Name))), 0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(string(profile.UserData)))), 0)
}

type eapWlanConnectionParameters struct {
	Mode    uint32
	Profile *uint16
	SSID    unsafe.Pointer
	BSSIDs  unsafe.Pointer
	BSSType uint32
	Flags   uint32
}

func (client *eapWlanClient) connect(name string) error {
	parameters := eapWlanConnectionParameters{Profile: windows.StringToUTF16Ptr(name), BSSType: 1}
	return callEAPWlan(eapWlanConnect, client.handle, uintptr(unsafe.Pointer(&client.guid)), uintptr(unsafe.Pointer(&parameters)), 0)
}

func (client *eapWlanClient) remove(name string, expected []byte) error {
	actual, present, err := client.get(name)
	if err != nil || !present {
		return err
	}
	if err := matchEAPWindowsXML(actual, expected); err != nil {
		return err
	}
	var size, valueType uint32
	var attributes unsafe.Pointer
	err = callEAPWlan(eapWlanQuery, client.handle, uintptr(unsafe.Pointer(&client.guid)), 7, 0, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&attributes)), uintptr(unsafe.Pointer(&valueType)))
	if err == nil {
		defer eapWlanFree.Call(uintptr(attributes))
		if attributes == nil || size < 8+256*2 || size > 4096 {
			return errors.New("Windows EAP connection readback has an invalid size")
		}
		current := windows.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Add(attributes, 8)), 256))
		if current == name {
			if err := callEAPWlan(eapWlanDisconnect, client.handle, uintptr(unsafe.Pointer(&client.guid)), 0); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, windows.ERROR_INVALID_STATE) {
		return err
	}
	if err := callEAPWlan(eapWlanDelete, client.handle, uintptr(unsafe.Pointer(&client.guid)), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), 0); err != nil {
		return err
	}
	_, present, err = client.get(name)
	if err != nil || present {
		return errors.New("Windows EAP wireless profile removal was not confirmed")
	}
	return nil
}
