//go:build darwin && !cgo

package endpointservice

import (
	"context"
	"errors"
)

func darwinEAPAdapters(context.Context) ([]EAPAdapter, error) {
	return nil, errors.New("macOS native EAP adapter inventory requires SystemConfiguration support")
}
