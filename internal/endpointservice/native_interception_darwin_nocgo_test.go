//go:build darwin && !cgo

package endpointservice

import "testing"

func TestDarwinNativeNoCGO(t *testing.T) {
	p, err := newNativeInterceptionPlatform(Config{}, nil)
	if err == nil || p != nil {
		t.Fatal("native interception accepted without cgo")
	}
}
