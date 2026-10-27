//go:build darwin && cgo

package endpointservice

import (
	"context"
	"net"
	"testing"
)

func TestDarwinEAPAdaptersReadSystemServiceOrder(t *testing.T) {
	adapters, err := darwinEAPAdapters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(adapters) == 0 {
		t.Fatal("no configured physical network service was returned")
	}
	seen := map[string]bool{}
	position := 0
	for _, adapter := range adapters {
		if !identifierPattern.MatchString(adapter.ID) || adapter.Name == "" || seen[adapter.Name] {
			t.Fatalf("invalid adapter identity: %+v", adapter)
		}
		seen[adapter.Name] = true
		if _, err := net.InterfaceByName(adapter.Name); err != nil {
			t.Fatal(err)
		}
		if adapter.Medium == "wired" {
			if adapter.EthernetPosition <= position {
				t.Fatal("Ethernet order was not preserved")
			}
			position = adapter.EthernetPosition
		} else if adapter.Medium != "wifi" || adapter.EthernetPosition != 0 {
			t.Fatalf("invalid medium: %+v", adapter)
		}
	}
}
