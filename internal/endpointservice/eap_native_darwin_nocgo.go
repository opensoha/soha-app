//go:build darwin && !cgo

package endpointservice

import (
	"context"
	"errors"
)

func darwinEAPIdentityReadback(context.Context, []byte) error {
	return errors.New("macOS EAP keychain readback requires the native service build")
}
func darwinEAPAssociate(context.Context, string, string, string, string, []byte) error {
	return errors.New("macOS EAP connection requires the native service build")
}
