package endpointservice

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// A short, independent watchdog also runs while control polling is blocked. It
// detects wake gaps and uplink changes before attempting a fresh connection.
func (manager *Manager) watchNetworkLifecycle(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var session, previous string
	last := time.Now().UnixNano()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		now := time.Now().UnixNano()
		gap := time.Duration(now - last)
		last = now
		status := manager.Status()
		if status.SessionID == "" {
			session, previous = "", ""
			continue
		}
		fingerprint, err := uplinkFingerprint()
		if err == nil && session != status.SessionID {
			session, previous = status.SessionID, fingerprint
			continue
		}
		reason := ""
		if err != nil {
			reason = "network_state_unavailable"
		} else if gap > 10*time.Second || gap < 0 {
			reason = "system_resume_requires_reconnect"
		} else if fingerprint != previous {
			reason = "network_changed_requires_reconnect"
		}
		if !manager.operationMu.TryLock() {
			continue
		}
		if manager.Status().SessionID != session {
			manager.operationMu.Unlock()
			continue
		}
		check, cancel := context.WithTimeout(ctx, 5*time.Second)
		if reason == "" && manager.options.CheckVPNHealth != nil {
			if err := manager.options.CheckVPNHealth(check); err != nil {
				reason = "vpn_health_changed"
			}
		}
		cancel()
		if reason == "" {
			manager.operationMu.Unlock()
			continue
		}
		if manager.Status().SessionID == session {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			_, _ = manager.disconnectLocked(cleanup, reason)
			cancel()
		}
		manager.operationMu.Unlock()
	}
}

func uplinkFingerprint() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	values := []string{}
	for _, adapter := range interfaces {
		name := strings.ToLower(adapter.Name)
		if adapter.Flags&net.FlagUp == 0 || adapter.Flags&net.FlagLoopback != 0 || name == strings.ToLower(endpointInterfaceName) || strings.HasPrefix(name, "utun") {
			continue
		}
		addresses, err := adapter.Addrs()
		if err != nil {
			return "", err
		}
		for _, raw := range addresses {
			prefix, err := netip.ParsePrefix(raw.String())
			if err == nil && prefix.Addr().IsGlobalUnicast() {
				values = append(values, fmt.Sprintf("%d/%s/%s", adapter.Index, adapter.HardwareAddr, prefix))
			}
		}
	}
	slices.Sort(values)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(values, "\n")))), nil
}
