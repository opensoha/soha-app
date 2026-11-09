package endpointservice

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
)

func nmEAPValueEqual(a, b any) bool {
	x, e1 := json.Marshal(a)
	y, e2 := json.Marshal(b)
	return e1 == nil && e2 == nil && bytes.Equal(x, y)
}

// Only these documented default values and the connection's activation timestamp
// are normalized. Unknown groups/properties, nondefault routes/DNS/master, and
// missing requested properties all fail closed. No secret or secret digest is kept.
func normalizeNMEAPSettings(settings nmEAPSettings) nmEAPSettings {
	defaults := map[string]map[string]any{
		"connection":               {"read-only": false, "autoconnect-priority": 0, "autoconnect-retries": -1, "auth-retries": -1, "gateway-ping-timeout": 0, "metered": 0, "multi-connect": 0, "lldp": -1, "mdns": -1, "llmnr": -1, "dns-over-tls": -1, "wait-device-timeout": -1, "zone": "", "master": "", "slave-type": "", "stable-id": ""},
		"802-1x":                   {"system-ca-certs": false, "optional": false},
		"802-3-ethernet":           {"mtu": 0, "speed": 0, "auto-negotiate": false, "duplex": "", "wake-on-lan": 1},
		"802-11-wireless":          {"mtu": 0, "hidden": false, "powersave": 0, "wake-on-wlan": 1, "channel": 0, "rate": 0, "tx-power": 0},
		"802-11-wireless-security": {"pmf": 0, "wep-tx-keyidx": 0, "auth-alg": "", "leap-username": ""},
		"proxy":                    {"method": 0, "browser-only": false, "pac-url": "", "pac-script": ""},
	}
	ipDefaults := map[string]any{"gateway": "", "route-metric": -1, "route-table": 0, "ignore-auto-routes": false, "ignore-auto-dns": false, "never-default": false, "may-fail": true, "dhcp-hostname": "", "dhcp-send-hostname": true, "dhcp-timeout": 0, "required-timeout": -1, "dad-timeout": -1}
	defaults["ipv4"], defaults["ipv6"] = ipDefaults, ipDefaults
	emptyKeys := map[string]map[string]bool{
		"connection":      {"permissions": true, "secondaries": true},
		"ipv4":            {"dns": true, "dns-search": true, "dns-options": true, "addresses": true, "address-data": true, "routes": true, "route-data": true},
		"ipv6":            {"dns": true, "dns-search": true, "dns-options": true, "addresses": true, "address-data": true, "routes": true, "route-data": true},
		"802-3-ethernet":  {"mac-address-blacklist": true},
		"802-11-wireless": {"mac-address-blacklist": true, "seen-bssids": true},
	}
	result := nmEAPSettings{}
	for group, values := range settings {
		clean := map[string]any{}
		for key, value := range values {
			if group == "connection" && key == "timestamp" {
				if _, ok := value.(uint64); ok {
					continue
				}
			}
			if want, ok := defaults[group][key]; ok && nmEAPValueEqual(value, want) {
				continue
			}
			v := reflect.ValueOf(value)
			if emptyKeys[group][key] && v.IsValid() && (v.Kind() == reflect.Slice || v.Kind() == reflect.Map) && v.Len() == 0 {
				continue
			}
			clean[key] = value
		}
		if len(clean) > 0 || defaults[group] == nil {
			result[group] = clean
		}
	}
	return result
}

func matchNMEAPSettings(expected, actual nmEAPSettings) error {
	if !nmEAPValueEqual(normalizeNMEAPSettings(expected), normalizeNMEAPSettings(actual)) {
		return errors.New("managed NetworkManager full settings changed; resource preserved")
	}
	return nil
}
