//go:build windows

package endpointservice

import "testing"

func TestWindowsEAPAdapterCleanupRetainsIdentityChecks(t *testing.T) {
	selected := EAPAdapter{ID: "{11111111-1111-1111-1111-111111111111}", Name: "Ethernet", Medium: "wired", MACAddress: "AA:BB:CC:DD:EE:FF", Enabled: true}
	current := selected
	current.Enabled = false
	current.MACAddress = "aa:bb:cc:dd:ee:ff"
	if err := matchWindowsEAPAdapter([]EAPAdapter{current}, selected, false); err != nil {
		t.Fatalf("owned, unavailable adapter cannot be cleaned up: %v", err)
	}
	if err := matchWindowsEAPAdapter([]EAPAdapter{current}, selected, true); err == nil {
		t.Fatal("installation/readback accepted an unavailable adapter")
	}
	if err := matchWindowsEAPAdapter(nil, selected, false); err == nil {
		t.Fatal("cleanup accepted a missing adapter")
	}
	for _, field := range []string{"id", "name", "medium", "mac"} {
		t.Run(field, func(t *testing.T) {
			changed := current
			switch field {
			case "id":
				changed.ID = "{22222222-2222-2222-2222-222222222222}"
			case "name":
				changed.Name = "Another Ethernet"
			case "medium":
				changed.Medium = "wifi"
			case "mac":
				changed.MACAddress = "11:22:33:44:55:66"
			}
			if err := matchWindowsEAPAdapter([]EAPAdapter{changed}, selected, false); err == nil {
				t.Fatalf("cleanup accepted a changed adapter %s", field)
			}
		})
	}
}
