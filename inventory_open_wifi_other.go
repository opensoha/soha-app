//go:build !darwin && !linux && !windows

package main

func observeCurrentOpenWiFiSSID() string { return "" }
