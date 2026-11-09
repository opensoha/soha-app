//go:build !windows

package endpointservice

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
)

type nativePreWALSession struct {
	nativeSession
	calls         int
	beforePrepare func()
}

func (s *nativePreWALSession) Validate(ctx context.Context, restore bool) error {
	if err := s.nativeSession.Validate(ctx, restore); err != nil {
		return err
	}
	if !restore {
		s.calls++
		if s.calls == 3 && s.beforePrepare != nil {
			s.beforePrepare()
		}
	}
	return nil
}

// Preparation has not installed a trusted control scope. A new process can
// bind the controller port between that failure and rollback (or its retry).
func TestNativeInterceptionQuiescePreWALFailureNeverFallsBack(t *testing.T) {
	for _, kind := range []string{"proof", "readback", "wal"} {
		t.Run(kind, func(t *testing.T) {
			e, c, p, api, peer, _ := nativeStageFixture(t)
			n := e.native
			var rebound atomic.Bool
			var oldRequests, newRequests, secrets atomic.Int32
			var once sync.Once
			rebind := func() {
				once.Do(func() {
					p.mu.Lock()
					p.dialErr = errors.New("owned incarnation is unknown after rebound")
					p.mu.Unlock()
					if err := api.listener.Close(); err != nil {
						t.Fatal(err)
					}
					listener, err := net.Listen("tcp", p.endpoint.String())
					if err != nil {
						t.Fatal(err)
					}
					server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						newRequests.Add(1)
						if r.Header.Get("Authorization") != "" {
							secrets.Add(1)
						}
						w.WriteHeader(http.StatusServiceUnavailable)
					}))
					server.Listener = listener
					server.Start()
					t.Cleanup(server.Close)
					rebound.Store(true)
				})
			}
			var blockedPath bool
			api.mu.Lock()
			api.beforeRequest = func(w http.ResponseWriter, r *http.Request) bool {
				if rebound.Load() {
					oldRequests.Add(1)
					if r.Header.Get("Authorization") != "" {
						secrets.Add(1)
					}
					w.WriteHeader(http.StatusServiceUnavailable)
					return true
				}
				if r.Method != http.MethodGet || r.URL.Path != "/configs" {
					return false
				}
				rebind()
				if kind == "readback" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return true
				}
				if kind == "wal" {
					if err := os.Rename(n.path, n.path+".before-test"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(n.path, 0700); err != nil {
						t.Fatal(err)
					}
					blockedPath = true
				}
				return false
			}
			api.mu.Unlock()
			session := &nativePreWALSession{nativeSession: peer.session}
			if kind == "proof" {
				session.beforePrepare = func() {
					p.process.mu.Lock()
					p.process.status.State = "stopping"
					p.process.mu.Unlock()
					rebind()
				}
			}
			peer.session = session
			// The ordinary fixture cleanup cannot recover this deliberately
			// unknown native owner. Release only our task-owned resources.
			t.Cleanup(func() {
				if n.dns != nil {
					n.dns.close()
				}
				if n.forward != nil {
					n.forward.close()
				}
				c.http.CloseIdleConnections()
				if err := c.Disable(context.Background()); err != nil {
					t.Error(err)
				}
			})
			status, err := e.SetInterception(context.Background(), peer, InterceptionIntent{RequestID: "native-prewal-" + kind, SystemProxy: true})
			if err == nil || !status.CleanupPending || !rebound.Load() {
				t.Fatal("pre-WAL failure not retained", status, err)
			}
			if blockedPath {
				if err := os.Remove(n.path); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(n.path+".before-test", n.path); err != nil {
					t.Fatal(err)
				}
			}
			if err := e.restoreNativeLocked(context.Background(), true); err == nil {
				t.Fatal("unknown owner cleanup succeeded")
			}
			// A second controller consumer must not bypass the native gate
			// while the required scope is missing (or not durably attached).
			c.mu.Lock()
			consumerErr := c.request(context.Background(), http.MethodGet, "/configs", nil, http.StatusOK, nil)
			c.mu.Unlock()
			if consumerErr == nil {
				t.Fatal("pending controller request succeeded")
			}
			if err := c.suspendNativeIngress(context.Background()); err == nil {
				t.Fatal("unpinned suspend succeeded")
			}
			if oldRequests.Load() != 0 || newRequests.Load() != 0 || secrets.Load() != 0 {
				t.Fatalf("rollback or pending consumer leaked application/secret: old=%d new=%d secrets=%d", oldRequests.Load(), newRequests.Load(), secrets.Load())
			}
			if p.writes != 0 || p.restores != 0 || c.nativeControl != nil || !c.nativeControlRequired || n.dns == nil || !p.alive.Load() {
				t.Fatal("failed preparation performed OS writes, attached an uncommitted scope, or discarded pending resources")
			}
		})
	}
}
