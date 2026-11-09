//go:build !windows

package endpointservice

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	api "github.com/opensoha/soha-contracts/gen/go/sohaapi"
)

func TestProjectedConfigurationAcknowledgementSurvivesSelectionNarrowingAndRestart(t *testing.T) {
	for _, mode := range []string{"mapped_nodes", "direct_subscription"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			configuration := twoNodeBundle(now)
			if mode == "direct_subscription" {
				p := configuration.Projection
				configuration.DirectProjection = &api.NetworkProxyDirectProjection{SchemaVersion: "proxy-direct/v1", RuntimeID: p.RuntimeID, ProfileID: p.ProfileID, BundleID: p.BundleID, Revision: p.Revision, ActiveRevision: p.ActiveRevision, SourceRevision: p.SourceRevision, OrgRevision: p.OrgRevision, ProjectionHash: p.ProjectionHash, ProcessEpoch: p.ProcessEpoch, ExpiresAt: p.ExpiresAt, DeliveryMode: "direct_subscription", UpstreamDisclosure: "upstream_parameters", Format: "mihomo_yaml", Groups: p.Groups, Rules: p.Rules, Content: "proxies:\n  - {name: node-a, type: http, server: 8.8.8.8, port: 443, password: fake-a}\n  - {name: node-b, type: http, server: 8.8.4.4, port: 443, password: fake-b}\n"}
				configuration.Projection = nil
				configuration.DeliveryMode = mode
			}
			secret := strings.Repeat("s", 32)
			server, fixture := newMihomoControllerFixture(t, secret)
			statePath := filepath.Join(t.TempDir(), "app.json")
			newExecutor := func() *CoordinatedExecutor {
				controller, err := NewMihomoController(server.URL, secret)
				if err != nil {
					t.Fatal(err)
				}
				configuration.ControllerPort = controller.port
				wg := &stoppedWireGuardFixture{fakeConfigurationExecutor: fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied", ReadbackHash: emptyReadbackHash()}}}
				executor, err := NewCoordinatedExecutor(wg, controller, statePath)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = executor.Disable(context.Background()) })
				return executor
			}
			executor := newExecutor()
			desired := ConfigurationDesired{ConfigurationVersion: 5, PolicyVersion: configuration.Protection.PolicyVersion, ValidUntil: configuration.EnforcementUntil, Mihomo: &configuration}
			first := executor.Apply(context.Background(), desired, now)
			if first.Status != "applied" {
				t.Fatalf("initial apply: %#v", first)
			}
			if _, err := executor.Proxy(context.Background(), &ProxyAction{Kind: "select", GroupID: configuration.SelectorGroup, NodeID: "node-b"}, nil); err != nil {
				t.Fatal(err)
			}
			if err := executor.Disable(context.Background()); err != nil {
				t.Fatal(err)
			}
			// A fresh service applies the current, independently delivered group choice.
			if configuration.Projection != nil {
				configuration.Projection.Groups[0].SelectedNodeID = "node-b"
			} else {
				configuration.DirectProjection.Groups[0].SelectedNodeID = "node-b"
			}
			executor = newExecutor()
			selected := executor.Apply(context.Background(), desired, now)
			if selected.Status != "applied" || selected.ReadbackHash != first.ReadbackHash {
				t.Fatalf("selection restart changed receipt: %#v, initial %#v", selected, first)
			}
			if err := executor.Disable(context.Background()); err != nil {
				t.Fatal(err)
			}
			configuration = narrowedBundle(t, configuration)
			executor = newExecutor()
			narrowed := executor.Apply(context.Background(), desired, now)
			if narrowed.Status != "applied" || narrowed.ReadbackHash != first.ReadbackHash {
				t.Fatalf("narrowed restart changed receipt: %#v, initial %#v", narrowed, first)
			}
			if verified := executor.Verify(context.Background(), desired, now); verified.Status != "applied" || verified.ReadbackHash != first.ReadbackHash {
				t.Fatalf("valid narrowed readback: %#v", verified)
			}
			// Receipt normalization must not hide actual controller policy drift.
			fixture.mu.Lock()
			fixture.document.Rules = []string{"MATCH,DIRECT"}
			fixture.mu.Unlock()
			if verified := executor.Verify(context.Background(), desired, now); verified.Status != "rejected" || verified.ReasonCode != "mihomo_readback_mismatch" {
				t.Fatalf("policy drift accepted: %#v", verified)
			}
		})
	}
}

func TestProjectedConfigurationAcknowledgementPreservesFixedSelection(t *testing.T) {
	configuration := twoNodeBundle(time.Now().UTC())
	configuration.SelectedProxy = "node-a"
	readback := expectedMihomoReadback(configuration)
	first := mihomoConfigurationReadbackHash(&configuration, readback)
	readback.SelectedProxy = "node-b"
	if first == mihomoConfigurationReadbackHash(&configuration, readback) {
		t.Fatal("explicit fixed selection disappeared from receipt")
	}
	runtime := &ackWrongSelectionRuntime{}
	executor, err := NewCoordinatedExecutor(&fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied", ReadbackHash: emptyReadbackHash()}}, runtime)
	if err != nil {
		t.Fatal(err)
	}
	desired := ConfigurationDesired{PolicyVersion: configuration.Protection.PolicyVersion, ValidUntil: configuration.EnforcementUntil, Mihomo: &configuration}
	if outcome := executor.Apply(context.Background(), desired, time.Now()); outcome.Status != "rejected" || outcome.ReasonCode != "mihomo_apply_failed" {
		t.Fatalf("fixed selection mismatch accepted: %#v", outcome)
	}
	configuration.Projection = nil
	configuration.DeliveryMode = ""
	if mihomoConfigurationReadbackHash(&configuration, readback) != mihomoReadbackHash(readback) {
		t.Fatal("legacy receipt format changed")
	}
}

type ackWrongSelectionRuntime struct{ fakeMihomoRuntime }

func (r *ackWrongSelectionRuntime) Apply(_ context.Context, configuration MihomoConfiguration) (MihomoReadback, error) {
	readback := expectedMihomoReadback(configuration)
	readback.SelectedProxy = "node-b"
	return readback, nil
}
