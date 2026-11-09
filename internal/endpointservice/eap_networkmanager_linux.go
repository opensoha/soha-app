//go:build linux

package endpointservice

import (
	"context"
	"errors"
	"fmt"
	"github.com/godbus/dbus/v5"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
)

const nmName = "org.freedesktop.NetworkManager"
const nmRoot = dbus.ObjectPath("/org/freedesktop/NetworkManager")
const nmSettings = dbus.ObjectPath("/org/freedesktop/NetworkManager/Settings")

type nmDBusOps struct {
	conn  *dbus.Conn
	owner string
}

func newNMDBusOps(ctx context.Context) (*nmDBusOps, error) {
	c, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, errors.New("system D-Bus is unavailable")
	}
	o := &nmDBusOps{conn: c}
	if err := c.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, nmName).Store(&o.owner); err != nil {
		c.Close()
		return nil, errors.New("NetworkManager is unavailable")
	}
	return o, nil
}
func (o *nmDBusOps) Close() { _ = o.conn.Close() }
func (o *nmDBusOps) ownerCurrent(ctx context.Context) error {
	var owner string
	if err := o.conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, nmName).Store(&owner); err != nil || owner != o.owner {
		return errors.New("NetworkManager restarted; cleanup requires reconciliation")
	}
	return nil
}
func (o *nmDBusOps) get(ctx context.Context, path dbus.ObjectPath, iface, key string) (any, error) {
	var value dbus.Variant
	err := o.conn.Object(o.owner, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, iface, key).Store(&value)
	return value.Value(), err
}
func (o *nmDBusOps) Capability(ctx context.Context) (nmEAPCapability, error) {
	c := nmEAPCapability{Owner: o.owner}
	if err := o.ownerCurrent(ctx); err != nil {
		return c, err
	}
	v, err := o.get(ctx, nmRoot, nmName, "Version")
	if err != nil {
		return c, err
	}
	parts := strings.Split(fmt.Sprint(v), ".")
	if len(parts) < 2 {
		return c, errors.New("invalid NetworkManager version")
	}
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	if major < 1 || major == 1 && minor < 42 {
		return c, errors.New("NetworkManager 1.42 or newer is required")
	}
	var xml string
	if err := o.conn.Object(o.owner, nmSettings).CallWithContext(ctx, "org.freedesktop.DBus.Introspectable.Introspect", 0).Store(&xml); err != nil || !strings.Contains(xml, `name="AddConnection2"`) {
		return c, errors.New("NetworkManager AddConnection2 is unavailable")
	}
	var methods dbus.Variant
	if err := o.conn.Object("fi.w1.wpa_supplicant1", "/fi/w1/wpa_supplicant1").CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, "fi.w1.wpa_supplicant1", "EapMethods").Store(&methods); err != nil {
		return c, errors.New("supplicant method capabilities are unavailable")
	}
	supported, ok := methods.Value().([]string)
	if !ok {
		return c, errors.New("supplicant method capabilities are invalid")
	}
	c.AddConnection2, c.ExactServerMatch, c.TLS12 = true, true, true
	c.TLS = slices.Contains(supported, "TLS")
	c.TTLSPAP = slices.Contains(supported, "TTLS")
	// WPA3 requires per-device cipher/key-management evidence; do not infer it from a version.
	return c, nil
}
func (o *nmDBusOps) devices(ctx context.Context) ([]nmEAPDevice, error) {
	var paths []dbus.ObjectPath
	if err := o.conn.Object(o.owner, nmRoot).CallWithContext(ctx, nmName+".GetDevices", 0).Store(&paths); err != nil {
		return nil, err
	}
	if len(paths) > 128 {
		return nil, errors.New("too many NetworkManager devices")
	}
	var result []nmEAPDevice
	for _, path := range paths {
		d, err := o.device(ctx, path)
		if err == nil {
			result = append(result, d)
		}
	}
	return result, nil
}
func (o *nmDBusOps) device(ctx context.Context, path dbus.ObjectPath) (nmEAPDevice, error) {
	d := nmEAPDevice{Path: string(path)}
	typ, err := o.get(ctx, path, nmName+".Device", "DeviceType")
	if err != nil {
		return d, err
	}
	iface := ""
	switch typ {
	case uint32(1):
		d.Medium = "wired"
		iface = nmName + ".Device.Wired"
	case uint32(2):
		d.Medium = "wifi"
		iface = nmName + ".Device.Wireless"
	default:
		return d, errors.New("unsupported NetworkManager device")
	}
	name, err := o.get(ctx, path, nmName+".Device", "Interface")
	if err != nil {
		return d, err
	}
	d.Interface, _ = name.(string)
	mac, err := o.get(ctx, path, iface, "PermHwAddress")
	if err != nil {
		mac, err = o.get(ctx, path, iface, "HwAddress")
	}
	if err != nil {
		return d, err
	}
	d.MAC, _ = mac.(string)
	managed, err := o.get(ctx, path, nmName+".Device", "Managed")
	d.Managed, _ = managed.(bool)
	return d, err
}
func nmVariants(s nmEAPSettings) map[string]map[string]dbus.Variant {
	r := map[string]map[string]dbus.Variant{}
	for group, values := range s {
		r[group] = map[string]dbus.Variant{}
		for k, v := range values {
			r[group][k] = dbus.MakeVariant(v)
		}
	}
	return r
}
func (o *nmDBusOps) Add(ctx context.Context, s nmEAPSettings, flags uint32) (string, error) {
	if err := o.ownerCurrent(ctx); err != nil {
		return "", err
	}
	var path dbus.ObjectPath
	var result map[string]dbus.Variant
	err := o.conn.Object(o.owner, nmSettings).CallWithContext(ctx, nmName+".Settings.AddConnection2", 0, nmVariants(s), flags, map[string]dbus.Variant{}).Store(&path, &result)
	return string(path), err
}
func (o *nmDBusOps) resolve(ctx context.Context, r nmEAPReceipt) (dbus.ObjectPath, error) {
	if err := o.ownerCurrent(ctx); err != nil {
		return "", err
	}
	var path dbus.ObjectPath
	err := o.conn.Object(o.owner, nmSettings).CallWithContext(ctx, nmName+".Settings.GetConnectionByUuid", 0, r.UUID).Store(&path)
	if err != nil {
		// Only this exact UUID lookup can prove absence. UnknownObject and
		// errors from settings/device readback leave the receipt unresolved.
		var e dbus.Error
		if errors.As(err, &e) && e.Name == nmName+".Settings.InvalidConnection" {
			if err := o.ownerCurrent(ctx); err != nil {
				return "", err
			}
			return "", errNMEAPConnectionAbsent
		}
		return "", err
	}
	if r.Owner != o.owner {
		return "", errors.New("NetworkManager incarnation changed; current connection was preserved")
	}
	if r.ConnectionPath != "" && string(path) != r.ConnectionPath {
		return "", errors.New("managed connection object changed")
	}
	return path, nil
}
func (o *nmDBusOps) Inspect(ctx context.Context, r nmEAPReceipt) (nmEAPReceipt, error) {
	path, err := o.resolve(ctx, r)
	if err != nil {
		return r, err
	}
	d, err := o.device(ctx, dbus.ObjectPath(r.Device.Path))
	if err != nil || !reflect.DeepEqual(d, r.Device) {
		return r, errors.New("NetworkManager device changed")
	}
	var actual map[string]map[string]dbus.Variant
	if err := o.conn.Object(o.owner, path).CallWithContext(ctx, nmName+".Settings.Connection.GetSettings", 0).Store(&actual); err != nil {
		return r, err
	}
	full := nmEAPSettings{}
	for group, values := range actual {
		full[group] = map[string]any{}
		for key, value := range values {
			full[group][key] = value.Value()
		}
	}
	if err := matchNMEAPSettings(r.Settings, full); err != nil {
		return r, err
	}
	flags, err := o.get(ctx, path, nmName+".Settings.Connection", "Unsaved")
	if err != nil || flags != true {
		return r, errors.New("managed EAP connection was persisted outside Soha")
	}
	r.ConnectionPath = string(path)
	return r, nil
}
func (o *nmDBusOps) Activate(ctx context.Context, r nmEAPReceipt) error {
	if _, err := o.Inspect(ctx, r); err != nil {
		return err
	}
	var active dbus.ObjectPath
	return o.conn.Object(o.owner, nmRoot).CallWithContext(ctx, nmName+".ActivateConnection", 0, dbus.ObjectPath(r.ConnectionPath), dbus.ObjectPath(r.Device.Path), dbus.ObjectPath("/")).Store(&active)
}
func (o *nmDBusOps) active(ctx context.Context, r nmEAPReceipt) (string, bool, error) {
	value, err := o.get(ctx, dbus.ObjectPath(r.Device.Path), nmName+".Device", "ActiveConnection")
	if err != nil {
		return "", false, err
	}
	path, ok := value.(dbus.ObjectPath)
	if !ok || !path.IsValid() {
		return "", false, errors.New("invalid NetworkManager active connection")
	}
	if path == "/" {
		return "", false, nil
	}
	value, err = o.get(ctx, path, nmName+".Connection.Active", "Uuid")
	if err != nil {
		return "", false, err
	}
	uuid, ok := value.(string)
	if !ok || uuid == "" {
		return "", false, errors.New("invalid NetworkManager active connection UUID")
	}
	if uuid != r.UUID {
		return string(path), false, nil
	}
	settings, err := o.get(ctx, path, nmName+".Connection.Active", "Connection")
	if err != nil || settings != dbus.ObjectPath(r.ConnectionPath) {
		return "", false, errors.New("managed active connection identity changed")
	}
	return string(path), true, nil
}
func (o *nmDBusOps) WaitActivated(ctx context.Context, r nmEAPReceipt) error {
	timer := time.NewTicker(200 * time.Millisecond)
	defer timer.Stop()
	for {
		path, owned, err := o.active(ctx, r)
		if err != nil {
			return err
		}
		if owned {
			value, err := o.get(ctx, dbus.ObjectPath(path), nmName+".Connection.Active", "State")
			if err != nil {
				return err
			}
			state, ok := value.(uint32)
			if !ok {
				return errors.New("invalid NetworkManager active connection state")
			}
			if state == 2 {
				return nil
			}
			if state == 4 {
				return errors.New("EAP activation was rejected")
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func (o *nmDBusOps) RemoveOwned(ctx context.Context, r nmEAPReceipt) error {
	return removeNMEAPProfile(ctx, o, r)
}

func (o *nmDBusOps) deactivate(ctx context.Context, active string) error {
	return o.conn.Object(o.owner, nmRoot).CallWithContext(ctx, nmName+".DeactivateConnection", 0, dbus.ObjectPath(active)).Err
}

func (o *nmDBusOps) deleteConnection(ctx context.Context, path string) error {
	return o.conn.Object(o.owner, dbus.ObjectPath(path)).CallWithContext(ctx, nmName+".Settings.Connection.Delete", 0).Err
}

func dbusPath(s string) dbus.ObjectPath { return dbus.ObjectPath(s) }
