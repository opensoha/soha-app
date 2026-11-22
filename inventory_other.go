//go:build !darwin

package main

import "runtime"

func collectPlatformFacts() (string, EndpointDeviceReportedFacts) {
	return inferDeviceType(runtime.GOOS, "", false), EndpointDeviceReportedFacts{OSName: runtime.GOOS}
}

func collectNetworkLinkStatus() NetworkLinkStatus {
	status := observedNetworkAddress()
	if status.Connected {
		if ssid := observeCurrentOpenWiFiSSID(); ssid != "" {
			status.Medium = "wifi"
			status.OpenWiFiSSID = ssid
		}
	}
	return status
}
