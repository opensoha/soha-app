//go:build darwin && !ios && !server

package main

import (
	"github.com/wailsapp/wails/v3/pkg/mac"
)

func validateAppInstancePlatform(instance appInstance) error {
	return validateAppInstanceBundleID(instance, mac.GetBundleID())
}
