package endpointservice

import (
	"context"
	"os"
	"testing"
)

func TestMihomoControllerIntegration(t *testing.T) {
	origin, secret, subscription := os.Getenv("SOHA_MIHOMO_INTEGRATION_URL"), os.Getenv("SOHA_MIHOMO_INTEGRATION_SECRET"), os.Getenv("SOHA_MIHOMO_INTEGRATION_SUBSCRIPTION_URL")
	if origin == "" || secret == "" || subscription == "" {
		t.Skip("mihomo integration environment is not configured")
	}
	controller, err := NewMihomoController(origin, secret)
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := mihomoOrigin(origin)
	configuration := managedMihomoConfiguration(port)
	configuration.SubscriptionURL = subscription
	if _, err := controller.Apply(context.Background(), configuration); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := controller.ProxyFlowSnapshot(context.Background()); err != nil || !snapshot.Active || snapshot.Engine != "mihomo" || snapshot.SelectedProxy != "edge-a" || snapshot.ActiveConnections < 0 {
		t.Fatalf("flow snapshot = %#v, %v", snapshot, err)
	}
	if err := controller.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	var readback struct {
		MixedPort int    `json:"mixed-port"`
		Mode      string `json:"mode"`
	}
	if err := controller.request(context.Background(), "GET", "/configs", nil, 200, &readback); err != nil || readback.MixedPort != 0 || readback.Mode != "direct" {
		t.Fatalf("disabled readback = %#v, %v", readback, err)
	}
}
