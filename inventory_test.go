package main

import (
	"net"
	"testing"
)

func TestEndpointInventoryClassification(t *testing.T) {
	if got := inferDeviceType("darwin", "MacBookAir15,2", false); got != "laptop" {
		t.Fatalf("MacBook device type = %q", got)
	}
	if got := inferDeviceType("darwin", "Mac16,12", true); got != "laptop" {
		t.Fatalf("battery-backed Mac device type = %q", got)
	}
	if got := networkInterfaceKind("utun4", 0); got != "virtual" {
		t.Fatalf("utun interface kind = %q", got)
	}
	if got := networkInterfaceKind("lo0", net.FlagLoopback); got != "loopback" {
		t.Fatalf("loopback interface kind = %q", got)
	}
	address, family, ok := parseInterfaceAddress("fe80::1%en0/64")
	if !ok || address != "fe80::1" || family != 6 {
		t.Fatalf("parsed interface address = %q, %d, %v", address, family, ok)
	}
	route := "gateway: 10.0.3.254\n  interface: en0\n"
	if got := parseNetworkValue(route, "interface"); got != "en0" {
		t.Fatalf("parsed interface = %q", got)
	}
	dns := parseDNSServers("nameserver[0] : 10.0.0.53\nnameserver[0] : 10.0.0.53\nnameserver[1] : invalid\n")
	if len(dns) != 1 || dns[0] != "10.0.0.53" {
		t.Fatalf("parsed DNS servers = %#v", dns)
	}
}
