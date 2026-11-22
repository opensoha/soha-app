//go:build linux

package endpointservice

import (
	"bytes"
	"context"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"
)

const (
	openWiFiActiveConnectionInterface = "org.freedesktop.NetworkManager.Connection.Active"
	openWiFiDeviceInterface           = "org.freedesktop.NetworkManager.Device"
	openWiFiWirelessInterface         = "org.freedesktop.NetworkManager.Device.Wireless"
	openWiFiAccessPointInterface      = "org.freedesktop.NetworkManager.AccessPoint"
	nmActiveConnectionActivated       = 2
	nmWiFiInfrastructureMode          = 2
	nmAccessPointPrivacy              = 1
)

type openWiFiReader interface {
	get(context.Context, dbus.ObjectPath, string, string) (any, error)
	ownerCurrent(context.Context) error
}

// ObserveOpenWiFiSSID returns the SSID of the current primary open Wi-Fi
// connection, or an empty string when that cannot be established safely.
func ObserveOpenWiFiSSID(ctx context.Context) string {
	ops, err := newNMDBusOps(ctx)
	if err != nil {
		return ""
	}
	defer ops.Close()
	return observeOpenWiFiSSID(ctx, ops)
}

func observeOpenWiFiSSID(ctx context.Context, reader openWiFiReader) string {
	primary, ok := readOpenWiFiProperty[dbus.ObjectPath](ctx, reader, nmRoot, nmName, "PrimaryConnection")
	if !ok || !openWiFiValidObjectPath(primary) {
		return ""
	}

	state, ok := readOpenWiFiProperty[uint32](ctx, reader, primary, openWiFiActiveConnectionInterface, "State")
	if !ok || state != nmActiveConnectionActivated {
		return ""
	}

	connectionType, ok := readOpenWiFiProperty[string](ctx, reader, primary, openWiFiActiveConnectionInterface, "Type")
	if !ok || connectionType != "802-11-wireless" {
		return ""
	}

	isDefault, readIPv4 := readOpenWiFiProperty[bool](ctx, reader, primary, openWiFiActiveConnectionInterface, "Default")
	isDefault6, readIPv6 := readOpenWiFiProperty[bool](ctx, reader, primary, openWiFiActiveConnectionInterface, "Default6")
	if !readIPv4 || !readIPv6 || (!isDefault && !isDefault6) {
		return ""
	}

	devices, ok := readOpenWiFiProperty[[]dbus.ObjectPath](ctx, reader, primary, openWiFiActiveConnectionInterface, "Devices")
	if !ok || len(devices) != 1 || !openWiFiValidObjectPath(devices[0]) {
		return ""
	}
	device := devices[0]

	activeConnection, ok := readOpenWiFiProperty[dbus.ObjectPath](ctx, reader, device, openWiFiDeviceInterface, "ActiveConnection")
	if !ok || activeConnection != primary {
		return ""
	}

	accessPoint, ok := readOpenWiFiProperty[dbus.ObjectPath](ctx, reader, device, openWiFiWirelessInterface, "ActiveAccessPoint")
	if !ok || !openWiFiValidObjectPath(accessPoint) {
		return ""
	}

	mode, ok := readOpenWiFiProperty[uint32](ctx, reader, accessPoint, openWiFiAccessPointInterface, "Mode")
	if !ok || mode != nmWiFiInfrastructureMode {
		return ""
	}
	flags, ok := readOpenWiFiProperty[uint32](ctx, reader, accessPoint, openWiFiAccessPointInterface, "Flags")
	if !ok || flags&nmAccessPointPrivacy != 0 {
		return ""
	}
	for _, property := range []string{"WpaFlags", "RsnFlags"} {
		security, ok := readOpenWiFiProperty[uint32](ctx, reader, accessPoint, openWiFiAccessPointInterface, property)
		if !ok || security != 0 {
			return ""
		}
	}
	ssid, ok := readOpenWiFiProperty[[]byte](ctx, reader, accessPoint, openWiFiAccessPointInterface, "Ssid")
	if !ok || len(ssid) == 0 || len(ssid) > 32 || !utf8.Valid(ssid) || bytes.IndexByte(ssid, 0) >= 0 {
		return ""
	}

	// A roam or a default route change can occur during these separate reads.
	primaryAfter, ok := readOpenWiFiProperty[dbus.ObjectPath](ctx, reader, nmRoot, nmName, "PrimaryConnection")
	if !ok || primaryAfter != primary {
		return ""
	}
	activeConnectionAfter, ok := readOpenWiFiProperty[dbus.ObjectPath](ctx, reader, device, openWiFiDeviceInterface, "ActiveConnection")
	if !ok || activeConnectionAfter != primary {
		return ""
	}
	accessPointAfter, ok := readOpenWiFiProperty[dbus.ObjectPath](ctx, reader, device, openWiFiWirelessInterface, "ActiveAccessPoint")
	if !ok || accessPointAfter != accessPoint {
		return ""
	}
	if err := reader.ownerCurrent(ctx); err != nil {
		return ""
	}
	return string(ssid)
}

func readOpenWiFiProperty[T any](
	ctx context.Context, reader openWiFiReader, path dbus.ObjectPath, iface, key string,
) (T, bool) {
	value, err := reader.get(ctx, path, iface, key)
	typed, ok := value.(T)
	return typed, err == nil && ok
}

func openWiFiValidObjectPath(path dbus.ObjectPath) bool {
	return path.IsValid() && path != "/"
}
