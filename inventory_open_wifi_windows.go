package main

import (
	"runtime"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// WinRT interfaces inherit the six IInspectable slots. These ordinals
	// follow the Windows.Networking.Connectivity SDK interface definitions.
	winRTQueryInterface               = 0
	winRTRelease                      = 2
	winRTInternetConnectionProfile    = 7  // INetworkInformationStatics
	winRTNetworkConnectivityLevel     = 7  // IConnectionProfile
	winRTNetworkSecuritySettings      = 14 // IConnectionProfile
	winRTIsWLANConnectionProfile      = 7  // IConnectionProfile2
	winRTWLANConnectionProfileDetails = 9  // IConnectionProfile2
	winRTNetworkAuthenticationType    = 6  // INetworkSecuritySettings
	winRTNetworkEncryptionType        = 7  // INetworkSecuritySettings
	winRTConnectedSSID                = 6  // IWlanConnectionProfileDetails

	winRTInitMultithreaded = 1
	winRTChangedMode       = 0x80010106
	winRTOpen80211         = 2
	winRTEncryptionNone    = 0
)

var (
	winRTCombase                   = windows.NewLazySystemDLL("combase.dll")
	winRTRoInitialize              = winRTCombase.NewProc("RoInitialize")
	winRTRoUninitialize            = winRTCombase.NewProc("RoUninitialize")
	winRTRoGetActivationFactory    = winRTCombase.NewProc("RoGetActivationFactory")
	winRTWindowsCreateString       = winRTCombase.NewProc("WindowsCreateString")
	winRTWindowsDeleteString       = winRTCombase.NewProc("WindowsDeleteString")
	winRTWindowsGetStringRawBuffer = winRTCombase.NewProc("WindowsGetStringRawBuffer")
	winRTNetworkInformationIID     = windows.GUID{
		Data1: 0x5074f851, Data2: 0x950d, Data3: 0x4165,
		Data4: [8]byte{0x9c, 0x15, 0x36, 0x56, 0x19, 0x48, 0x1e, 0xea},
	}
	winRTConnectionProfile2IID = windows.GUID{
		Data1: 0xe2045145, Data2: 0x4c9f, Data3: 0x400c,
		Data4: [8]byte{0x91, 0x50, 0x7e, 0xc7, 0xd6, 0xe2, 0x88, 0x8a},
	}
)

type winRTObject struct {
	vtable *[15]uintptr
}

func (object *winRTObject) release() {
	// IUnknown::Release returns the remaining reference count.
	_, _, _ = syscall.SyscallN(object.vtable[winRTRelease], uintptr(unsafe.Pointer(object)))
}

func winRTRead[T any](object *winRTObject, method int) (T, bool) {
	var result T
	status, _, _ := syscall.SyscallN(
		object.vtable[method],
		uintptr(unsafe.Pointer(object)),
		uintptr(unsafe.Pointer(&result)),
	)
	return result, int32(status) >= 0
}

// The WinRT connection profile describes the current preferred connection
// without scanning or requesting precise location access.
func observeCurrentOpenWiFiSSID() string {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	status, _, _ := winRTRoInitialize.Call(winRTInitMultithreaded)
	if int32(status) >= 0 {
		defer func() {
			// RoUninitialize has no return value.
			_, _, _ = winRTRoUninitialize.Call()
		}()
	} else if uint32(status) != winRTChangedMode {
		return ""
	}

	factory := winRTNetworkInformationFactory()
	if factory == nil {
		return ""
	}
	defer factory.release()
	profile, ok := winRTRead[*winRTObject](factory, winRTInternetConnectionProfile)
	if !ok || profile == nil {
		return ""
	}
	defer profile.release()
	level, ok := winRTRead[int32](profile, winRTNetworkConnectivityLevel)
	if !ok || level <= 0 {
		return ""
	}

	var wlanProfile *winRTObject
	status, _, _ = syscall.SyscallN(
		profile.vtable[winRTQueryInterface],
		uintptr(unsafe.Pointer(profile)),
		uintptr(unsafe.Pointer(&winRTConnectionProfile2IID)),
		uintptr(unsafe.Pointer(&wlanProfile)),
	)
	if int32(status) < 0 || wlanProfile == nil {
		return ""
	}
	defer wlanProfile.release()
	wireless, ok := winRTRead[bool](wlanProfile, winRTIsWLANConnectionProfile)
	if !ok || !wireless || !winRTProfileIsOpen(profile) {
		return ""
	}
	details, ok := winRTRead[*winRTObject](wlanProfile, winRTWLANConnectionProfileDetails)
	if !ok || details == nil {
		return ""
	}
	defer details.release()
	ssid, ok := winRTRead[uintptr](details, winRTConnectedSSID)
	if !ok || ssid == 0 {
		return ""
	}
	defer winRTDeleteString(ssid)
	return winRTSSIDText(ssid)
}

func winRTNetworkInformationFactory() *winRTObject {
	class, _ := windows.UTF16FromString("Windows.Networking.Connectivity.NetworkInformation")
	var name uintptr
	status, _, _ := winRTWindowsCreateString.Call(
		uintptr(unsafe.Pointer(&class[0])),
		uintptr(len(class)-1),
		uintptr(unsafe.Pointer(&name)),
	)
	if int32(status) < 0 {
		return nil
	}
	defer winRTDeleteString(name)

	var factory *winRTObject
	status, _, _ = winRTRoGetActivationFactory.Call(
		name,
		uintptr(unsafe.Pointer(&winRTNetworkInformationIID)),
		uintptr(unsafe.Pointer(&factory)),
	)
	if int32(status) < 0 {
		return nil
	}
	return factory
}

func winRTDeleteString(value uintptr) {
	// WindowsDeleteString always returns S_OK.
	_, _, _ = winRTWindowsDeleteString.Call(value)
}

func winRTProfileIsOpen(profile *winRTObject) bool {
	security, ok := winRTRead[*winRTObject](profile, winRTNetworkSecuritySettings)
	if !ok || security == nil {
		return false
	}
	defer security.release()
	authentication, ok := winRTRead[int32](security, winRTNetworkAuthenticationType)
	if !ok || authentication != winRTOpen80211 {
		return false
	}
	encryption, ok := winRTRead[int32](security, winRTNetworkEncryptionType)
	return ok && encryption == winRTEncryptionNone
}

func winRTSSIDText(value uintptr) string {
	var length uint32
	address, _, _ := winRTWindowsGetStringRawBuffer.Call(value, uintptr(unsafe.Pointer(&length)))
	if address == 0 || length == 0 || length > 32 {
		return ""
	}
	// The buffer is owned by the HSTRING and valid until it is deleted.
	pointer := *(*unsafe.Pointer)(unsafe.Pointer(&address))
	ssid := string(utf16.Decode(unsafe.Slice((*uint16)(pointer), length)))
	if len(ssid) > 32 || strings.ContainsRune(ssid, 0) || strings.ContainsRune(ssid, '\uFFFD') {
		return ""
	}
	return ssid
}
