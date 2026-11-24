//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -framework Foundation -framework CoreWLAN
#include <stdlib.h>
size_t sohaOpenWiFiSSID(const char *, unsigned char *);
*/
import "C"

import (
	"strings"
	"unicode/utf8"
	"unsafe"
)

func observeOpenWiFiSSID(interfaceName string) string {
	name := C.CString(interfaceName)
	defer C.free(unsafe.Pointer(name))
	var ssid [32]byte
	size := int(C.sohaOpenWiFiSSID(name, (*C.uchar)(unsafe.Pointer(&ssid[0]))))
	if size < 1 || size > len(ssid) || !utf8.Valid(ssid[:size]) {
		return ""
	}
	value := string(ssid[:size])
	if strings.IndexByte(value, 0) >= 0 {
		return ""
	}
	return value
}
