package endpointservice

import (
	"reflect"
	"testing"
)

func TestDarwinDNSAddressesKeepBothFamilies(t *testing.T) {
	for _, test := range []struct {
		name       string
		addresses  []string
		ipv4, ipv6 []string
	}{
		{"ipv4", []string{"100.96.0.2"}, []string{"100.96.0.2"}, nil},
		{"ipv6", []string{"fd00::2"}, nil, []string{"fd00::2"}},
		{"dual_stack", []string{"100.96.0.2", "fd00::2"}, []string{"100.96.0.2"}, []string{"fd00::2"}},
		{"dual_stack_reverse", []string{"fd00::2", "100.96.0.2"}, []string{"100.96.0.2"}, []string{"fd00::2"}},
		{"multiple", []string{"fd00::2", "100.96.0.2", "100.96.0.3", "fd00::3"}, []string{"100.96.0.2", "100.96.0.3"}, []string{"fd00::2", "fd00::3"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ipv4, ipv6, err := splitDarwinDNSAddresses(test.addresses)
			if err != nil || !reflect.DeepEqual(ipv4, test.ipv4) || !reflect.DeepEqual(ipv6, test.ipv6) {
				t.Fatalf("address entities = %v / %v, %v; want %v / %v", ipv4, ipv6, err, test.ipv4, test.ipv6)
			}
		})
	}
}

func TestDarwinDNSAddressesRejectInvalidState(t *testing.T) {
	for _, addresses := range [][]string{nil, {"invalid"}, {"100.96.0.2/32"}, {"::ffff:192.0.2.1"}, {"fe80::1%en0"}, {"::"}, {"224.0.0.1"}, {"100.96.0.2", "invalid"}} {
		if ipv4, ipv6, err := splitDarwinDNSAddresses(addresses); err == nil || ipv4 != nil || ipv6 != nil {
			t.Fatalf("invalid address state accepted: %v -> %v / %v, %v", addresses, ipv4, ipv6, err)
		}
	}
}
