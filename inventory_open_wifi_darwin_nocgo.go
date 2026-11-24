//go:build darwin && !cgo

package main

func observeOpenWiFiSSID(string) string { return "" }
