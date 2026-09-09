package main

import (
	"net"
	"net/netip"
	"runtime"
	"sort"
	"strings"
	"time"
)

type EndpointDeviceReportedFacts struct {
	OSName            string                     `json:"osName,omitempty"`
	OSVersion         string                     `json:"osVersion,omitempty"`
	OSBuild           string                     `json:"osBuild,omitempty"`
	Architecture      string                     `json:"architecture"`
	Manufacturer      string                     `json:"manufacturer,omitempty"`
	Model             string                     `json:"model,omitempty"`
	SerialNumber      string                     `json:"serialNumber,omitempty"`
	AgentVersion      string                     `json:"agentVersion"`
	CollectedAt       time.Time                  `json:"collectedAt"`
	NetworkInterfaces []EndpointNetworkInterface `json:"networkInterfaces"`
}

type EndpointNetworkInterface struct {
	Name          string   `json:"name"`
	DisplayName   string   `json:"displayName,omitempty"`
	Kind          string   `json:"kind"`
	Status        string   `json:"status"`
	MACAddress    string   `json:"macAddress,omitempty"`
	IPv4Addresses []string `json:"ipv4Addresses"`
	IPv6Addresses []string `json:"ipv6Addresses"`
	DNSServers    []string `json:"dnsServers,omitempty"`
}

type NetworkLinkStatus struct {
	Connected     bool     `json:"connected"`
	Medium        string   `json:"medium,omitempty"`
	InterfaceName string   `json:"interfaceName,omitempty"`
	IPAddress     string   `json:"ipAddress,omitempty"`
	Gateway       string   `json:"gateway,omitempty"`
	DNSServers    []string `json:"dnsServers"`
}

func collectEndpointInventory(appVersion string, collectedAt time.Time) (string, EndpointDeviceReportedFacts) {
	deviceType, facts := collectPlatformFacts()
	facts.Architecture = runtime.GOARCH
	facts.AgentVersion = appVersion
	facts.CollectedAt = collectedAt.UTC()
	facts.NetworkInterfaces = collectNetworkInterfaces()
	return deviceType, facts
}

func collectNetworkInterfaces() []EndpointNetworkInterface {
	interfaces, err := net.Interfaces()
	if err != nil {
		return []EndpointNetworkInterface{}
	}
	sort.Slice(interfaces, func(left, right int) bool { return interfaces[left].Name < interfaces[right].Name })
	if len(interfaces) > 64 {
		interfaces = interfaces[:64]
	}
	result := make([]EndpointNetworkInterface, 0, len(interfaces))
	for _, item := range interfaces {
		status := "down"
		if item.Flags&net.FlagUp != 0 {
			status = "up"
		}
		entry := EndpointNetworkInterface{
			Name: item.Name, Kind: networkInterfaceKind(item.Name, item.Flags), Status: status,
			IPv4Addresses: []string{}, IPv6Addresses: []string{},
		}
		if len(item.HardwareAddr) == 6 {
			entry.MACAddress = strings.ToLower(item.HardwareAddr.String())
		}
		addresses, _ := item.Addrs()
		for _, raw := range addresses {
			address, family, ok := parseInterfaceAddress(raw.String())
			if !ok {
				continue
			}
			if family == 4 && len(entry.IPv4Addresses) < 32 {
				entry.IPv4Addresses = append(entry.IPv4Addresses, address)
			}
			if family == 6 && len(entry.IPv6Addresses) < 32 {
				entry.IPv6Addresses = append(entry.IPv6Addresses, address)
			}
		}
		sort.Strings(entry.IPv4Addresses)
		sort.Strings(entry.IPv6Addresses)
		result = append(result, entry)
	}
	return result
}

func inferDeviceType(platform, model string, portable bool) string {
	if platform == "darwin" {
		switch {
		case strings.HasPrefix(model, "MacBook"), portable:
			return "laptop"
		case strings.HasPrefix(model, "iMac"), strings.HasPrefix(model, "Macmini"), strings.HasPrefix(model, "MacPro"), strings.HasPrefix(model, "MacStudio"):
			return "desktop"
		}
	}
	if platform == "android" || platform == "ios" {
		return "mobile"
	}
	return "unknown"
}

func networkInterfaceKind(name string, flags net.Flags) string {
	if flags&net.FlagLoopback != 0 {
		return "loopback"
	}
	lower := strings.ToLower(name)
	// ponytail: interface names are a bounded portability heuristic; replace with OS APIs when policy needs physical-adapter certainty.
	for _, prefix := range []string{"utun", "tun", "tap", "wg", "bridge", "awdl", "llw", "gif", "stf", "anpi", "vnic", "vmnet", "docker", "veth"} {
		if strings.HasPrefix(lower, prefix) {
			return "virtual"
		}
	}
	return "physical"
}

func parseInterfaceAddress(raw string) (string, int, bool) {
	host := raw
	if slash := strings.IndexByte(host, '/'); slash >= 0 {
		host = host[:slash]
	}
	if zone := strings.IndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return "", 0, false
	}
	if address.Is4() || address.Is4In6() {
		return address.Unmap().String(), 4, true
	}
	return address.String(), 6, true
}

func parseNetworkValue(output, name string) string {
	for _, line := range strings.Split(output, "\n") {
		key, value, found := strings.Cut(line, ":")
		if found && strings.TrimSpace(key) == name {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func parseDNSServers(output string) []string {
	servers := []string{}
	seen := map[string]struct{}{}
	for _, line := range strings.Split(output, "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found || !strings.HasPrefix(strings.TrimSpace(key), "nameserver[") {
			continue
		}
		address, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil {
			continue
		}
		server := address.Unmap().String()
		if _, exists := seen[server]; exists {
			continue
		}
		seen[server] = struct{}{}
		servers = append(servers, server)
		if len(servers) == 8 {
			break
		}
	}
	return servers
}
