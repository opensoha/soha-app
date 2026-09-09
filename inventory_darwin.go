//go:build darwin

package main

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

func collectPlatformFacts() (string, EndpointDeviceReportedFacts) {
	model := systemValue("/usr/sbin/sysctl", "-n", "hw.model")
	return inferDeviceType("darwin", model, hasInternalBattery()), EndpointDeviceReportedFacts{
		OSName:       firstNonEmpty(systemValue("/usr/bin/sw_vers", "-productName"), "macOS"),
		OSVersion:    systemValue("/usr/bin/sw_vers", "-productVersion"),
		OSBuild:      systemValue("/usr/bin/sw_vers", "-buildVersion"),
		Manufacturer: "Apple",
		Model:        model,
		SerialNumber: parseIOPlatformSerial(systemValue("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice")),
	}
}

func collectNetworkLinkStatus() NetworkLinkStatus {
	route := systemValue("/sbin/route", "-n", "get", "default")
	interfaceName := parseNetworkValue(route, "interface")
	status := NetworkLinkStatus{
		InterfaceName: interfaceName,
		Gateway:       parseNetworkValue(route, "gateway"),
		DNSServers:    parseDNSServers(systemValue("/usr/sbin/scutil", "--dns")),
	}
	for _, item := range collectNetworkInterfaces() {
		if item.Name == interfaceName && len(item.IPv4Addresses) > 0 {
			status.IPAddress = item.IPv4Addresses[0]
			break
		}
	}
	if interfaceName == "" || status.IPAddress == "" {
		return status
	}
	status.Connected = true
	status.Medium = "wired"
	if strings.Contains(systemValue("/usr/sbin/ipconfig", "getsummary", interfaceName), "InterfaceType : WiFi") {
		status.Medium = "wifi"
	}
	return status
}

func hasInternalBattery() bool {
	return strings.Contains(systemValue("/usr/sbin/ioreg", "-r", "-c", "AppleSmartBattery", "-d", "1"), "AppleSmartBattery")
}

func systemValue(path string, arguments ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, path, arguments...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func parseIOPlatformSerial(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "IOPlatformSerialNumber") {
			continue
		}
		_, value, found := strings.Cut(line, "=")
		if found {
			return strings.Trim(strings.TrimSpace(value), `"`)
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
