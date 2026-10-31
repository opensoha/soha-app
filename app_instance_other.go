//go:build !darwin || ios || server

package main

import (
	"errors"
	"runtime"
)

func validateAppInstancePlatform(instance appInstance) error {
	if instance.profile != "" && runtime.GOOS != "windows" {
		return errors.New("named App profiles require isolated macOS bundles or Windows WebView2; this platform is not supported yet")
	}
	return nil
}
