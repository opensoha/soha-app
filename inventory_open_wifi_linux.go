package main

import (
	"context"
	"time"

	"github.com/opensoha/soha-app/internal/endpointservice"
)

func observeCurrentOpenWiFiSSID() string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return endpointservice.ObserveOpenWiFiSSID(ctx)
}
