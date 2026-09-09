//go:build !darwin

package main

import "runtime"

func collectPlatformFacts() (string, EndpointDeviceReportedFacts) {
	return inferDeviceType(runtime.GOOS, "", false), EndpointDeviceReportedFacts{OSName: runtime.GOOS}
}

func collectNetworkLinkStatus() NetworkLinkStatus {
	return NetworkLinkStatus{DNSServers: []string{}}
}
