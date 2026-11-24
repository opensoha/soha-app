//go:build linux

package endpointservice

import (
	"context"
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"
)

const (
	openWiFiTestPrimary  = dbus.ObjectPath("/org/freedesktop/NetworkManager/ActiveConnection/2")
	openWiFiTestDevice   = dbus.ObjectPath("/org/freedesktop/NetworkManager/Devices/3")
	openWiFiTestAccessPt = dbus.ObjectPath("/org/freedesktop/NetworkManager/AccessPoint/4")
)

type openWiFiTestKey struct {
	path       dbus.ObjectPath
	iface, key string
}

type openWiFiTestReader struct {
	values   map[openWiFiTestKey]any
	reads    map[openWiFiTestKey]int
	before   func(openWiFiTestKey, int)
	ownerErr error
}

func newOpenWiFiTestReader() *openWiFiTestReader {
	r := &openWiFiTestReader{values: map[openWiFiTestKey]any{}, reads: map[openWiFiTestKey]int{}}
	r.set(nmRoot, nmName, "PrimaryConnection", openWiFiTestPrimary)
	r.set(openWiFiTestPrimary, openWiFiActiveConnectionInterface, "State", uint32(2))
	r.set(openWiFiTestPrimary, openWiFiActiveConnectionInterface, "Type", "802-11-wireless")
	r.set(openWiFiTestPrimary, openWiFiActiveConnectionInterface, "Default", false)
	r.set(openWiFiTestPrimary, openWiFiActiveConnectionInterface, "Default6", true)
	r.set(openWiFiTestPrimary, openWiFiActiveConnectionInterface, "Devices", []dbus.ObjectPath{openWiFiTestDevice})
	r.set(openWiFiTestDevice, openWiFiDeviceInterface, "ActiveConnection", openWiFiTestPrimary)
	r.set(openWiFiTestDevice, openWiFiWirelessInterface, "ActiveAccessPoint", openWiFiTestAccessPt)
	r.set(openWiFiTestAccessPt, openWiFiAccessPointInterface, "Mode", uint32(2))
	r.set(openWiFiTestAccessPt, openWiFiAccessPointInterface, "Flags", uint32(0))
	r.set(openWiFiTestAccessPt, openWiFiAccessPointInterface, "WpaFlags", uint32(0))
	r.set(openWiFiTestAccessPt, openWiFiAccessPointInterface, "RsnFlags", uint32(0))
	r.set(openWiFiTestAccessPt, openWiFiAccessPointInterface, "Ssid", []byte("Open Guest"))
	return r
}

func (r *openWiFiTestReader) set(path dbus.ObjectPath, iface, key string, value any) {
	r.values[openWiFiTestKey{path: path, iface: iface, key: key}] = value
}

func (r *openWiFiTestReader) get(_ context.Context, path dbus.ObjectPath, iface, key string) (any, error) {
	k := openWiFiTestKey{path: path, iface: iface, key: key}
	r.reads[k]++
	if r.before != nil {
		r.before(k, r.reads[k])
	}
	value, ok := r.values[k]
	if !ok {
		return nil, errors.New("property unavailable")
	}
	return value, nil
}

func (r *openWiFiTestReader) ownerCurrent(context.Context) error {
	return r.ownerErr
}

func TestObserveOpenWiFiSSIDOpen(t *testing.T) {
	for _, test := range []struct {
		name       string
		isDefault  bool
		isDefault6 bool
		expected   string
	}{
		{name: "default6", isDefault: false, isDefault6: true, expected: "Open Guest"},
		{name: "default", isDefault: true, isDefault6: false, expected: "Open Guest"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := newOpenWiFiTestReader()
			r.set(openWiFiTestPrimary, openWiFiActiveConnectionInterface, "Default", test.isDefault)
			r.set(openWiFiTestPrimary, openWiFiActiveConnectionInterface, "Default6", test.isDefault6)
			if got := observeOpenWiFiSSID(context.Background(), r); got != test.expected {
				t.Fatalf("SSID = %q, want %q", got, test.expected)
			}
		})
	}
}

func TestObserveOpenWiFiSSIDRejectsSecuredNetworks(t *testing.T) {
	for _, test := range []struct {
		name  string
		key   string
		value uint32
	}{
		{name: "privacy flag", key: "Flags", value: 1},
		{name: "WPA flags", key: "WpaFlags", value: 1},
		{name: "RSN flags", key: "RsnFlags", value: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := newOpenWiFiTestReader()
			r.set(openWiFiTestAccessPt, openWiFiAccessPointInterface, test.key, test.value)
			if got := observeOpenWiFiSSID(context.Background(), r); got != "" {
				t.Fatalf("secured network returned SSID %q", got)
			}
		})
	}
}

func TestObserveOpenWiFiSSIDRequiresPrimaryWiFi(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*openWiFiTestReader)
	}{
		{
			name: "not wireless",
			mutate: func(r *openWiFiTestReader) {
				r.set(openWiFiTestPrimary, openWiFiActiveConnectionInterface, "Type", "802-3-ethernet")
			},
		},
		{
			name: "not default",
			mutate: func(r *openWiFiTestReader) {
				r.set(openWiFiTestPrimary, openWiFiActiveConnectionInterface, "Default", false)
				r.set(openWiFiTestPrimary, openWiFiActiveConnectionInterface, "Default6", false)
			},
		},
		{
			name: "multiple devices",
			mutate: func(r *openWiFiTestReader) {
				r.set(openWiFiTestPrimary, openWiFiActiveConnectionInterface, "Devices", []dbus.ObjectPath{openWiFiTestDevice, "/org/freedesktop/NetworkManager/Devices/5"})
			},
		},
		{
			name: "ad hoc Wi-Fi",
			mutate: func(r *openWiFiTestReader) {
				r.set(openWiFiTestAccessPt, openWiFiAccessPointInterface, "Mode", uint32(1))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := newOpenWiFiTestReader()
			test.mutate(r)
			if got := observeOpenWiFiSSID(context.Background(), r); got != "" {
				t.Fatalf("non-primary Wi-Fi network returned SSID %q", got)
			}
		})
	}
}

func TestObserveOpenWiFiSSIDRejectsChangingEvidence(t *testing.T) {
	for _, test := range []struct {
		name string
		arm  func(*openWiFiTestReader)
	}{
		{
			name: "primary connection changes",
			arm: func(r *openWiFiTestReader) {
				key := openWiFiTestKey{path: nmRoot, iface: nmName, key: "PrimaryConnection"}
				r.before = func(k openWiFiTestKey, read int) {
					if k == key && read == 2 {
						r.set(nmRoot, nmName, "PrimaryConnection", dbus.ObjectPath("/org/freedesktop/NetworkManager/ActiveConnection/6"))
					}
				}
			},
		},
		{
			name: "device active connection changes",
			arm: func(r *openWiFiTestReader) {
				key := openWiFiTestKey{path: openWiFiTestDevice, iface: openWiFiDeviceInterface, key: "ActiveConnection"}
				r.before = func(k openWiFiTestKey, read int) {
					if k == key && read == 2 {
						r.set(openWiFiTestDevice, openWiFiDeviceInterface, "ActiveConnection", dbus.ObjectPath("/org/freedesktop/NetworkManager/ActiveConnection/6"))
					}
				}
			},
		},
		{
			name: "active access point changes",
			arm: func(r *openWiFiTestReader) {
				key := openWiFiTestKey{path: openWiFiTestDevice, iface: openWiFiWirelessInterface, key: "ActiveAccessPoint"}
				r.before = func(k openWiFiTestKey, read int) {
					if k == key && read == 2 {
						r.set(openWiFiTestDevice, openWiFiWirelessInterface, "ActiveAccessPoint", dbus.ObjectPath("/org/freedesktop/NetworkManager/AccessPoint/7"))
					}
				}
			},
		},
		{
			name: "NetworkManager owner changes",
			arm: func(r *openWiFiTestReader) {
				r.ownerErr = errors.New("owner changed")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := newOpenWiFiTestReader()
			test.arm(r)
			if got := observeOpenWiFiSSID(context.Background(), r); got != "" {
				t.Fatalf("changing evidence returned SSID %q", got)
			}
		})
	}
}

func TestObserveOpenWiFiSSIDRejectsInvalidSSID(t *testing.T) {
	for _, test := range []struct {
		name  string
		value []byte
	}{
		{name: "empty", value: []byte{}},
		{name: "too long", value: []byte("123456789012345678901234567890123")},
		{name: "NUL", value: []byte("open\x00wifi")},
		{name: "invalid UTF-8", value: []byte{0xff}},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := newOpenWiFiTestReader()
			r.set(openWiFiTestAccessPt, openWiFiAccessPointInterface, "Ssid", test.value)
			if got := observeOpenWiFiSSID(context.Background(), r); got != "" {
				t.Fatalf("invalid SSID returned %q", got)
			}
		})
	}
}
