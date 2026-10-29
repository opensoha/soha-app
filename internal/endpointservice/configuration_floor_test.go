package endpointservice

import (
	"testing"
	"time"
)

func TestConfigurationFloorSeparatesIndependentVersions(t *testing.T) {
	manager := &Manager{options: ManagerOptions{ControlURL: "https://control.example.test", RuntimeID: "runtime-1", DeviceID: "device-1"}}
	desired := ConfigurationDesired{ConfigurationVersion: 5, PolicyVersion: 3, ValidUntil: time.Now().UTC().Add(time.Minute), AccessProfile: "onboarding"}
	if err := manager.rememberConfiguration(desired); err != nil {
		t.Fatal(err)
	}
	floor := manager.configurationFloor
	updated := desired
	updated.RuntimeIntervals = &RuntimeIntervals{HeartbeatIntervalSeconds: 75, ConfigurationPollIntervalSeconds: 80}
	updated.Admission = &AdmissionConfiguration{RestrictionEpoch: 7}
	if err := manager.rememberConfiguration(updated); err != nil || manager.configurationFloor != floor {
		t.Fatalf("independent versions changed enforcement floor: %+v, %v", manager.configurationFloor, err)
	}
	for name, mutate := range map[string]func(*ConfigurationDesired){
		"profile":           func(c *ConfigurationDesired) { c.AccessProfile = "full" },
		"expiry":            func(c *ConfigurationDesired) { c.ValidUntil = c.ValidUntil.Add(time.Minute) },
		"policy rollback":   func(c *ConfigurationDesired) { c.PolicyVersion-- },
		"version rollback":  func(c *ConfigurationDesired) { c.ConfigurationVersion-- },
		"protected targets": func(c *ConfigurationDesired) { c.ProtectedResourceIDs = []string{"resource-1"} },
		"tunnel": func(c *ConfigurationDesired) {
			c.WireGuard = &WireGuardConfiguration{Addresses: []string{"100.96.0.2/32"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := desired
			mutate(&candidate)
			if err := manager.rememberConfiguration(candidate); err == nil || manager.configurationFloor != floor {
				t.Fatalf("changed enforcement accepted or floor changed: %+v, %v", manager.configurationFloor, err)
			}
		})
	}
}
