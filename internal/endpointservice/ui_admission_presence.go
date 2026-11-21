package endpointservice

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"time"
)

type endpointUILogin struct {
	SubjectID string `json:"subjectId"`
	Epoch     string `json:"epoch"`
	SessionID string `json:"sessionId"`
}

type uiAdmissionPresence struct {
	server, subject string
	changed         chan struct{}
	mu              sync.Mutex
	current         NativeUIScope
	retired         map[string]struct{}
	login           endpointUILogin
	observed        time.Time
}

func (presence *UIProcessPresence) ConfigureAdmissionLease(config Config) error {
	if !config.StrictAdmissionUILease {
		return nil
	}
	if presence == nil {
		return errors.New("strict admission requires provisioned native UI authentication")
	}
	server, subject, err := config.nativeUIBinding()
	if err != nil {
		return err
	}
	presence.strict = &uiAdmissionPresence{server: server, subject: subject, changed: make(chan struct{}, 1), retired: make(map[string]struct{})}
	return nil
}

func (presence *UIProcessPresence) observeAdmissionScope(connection net.Conn, scope NativeUIScope, now time.Time) error {
	if presence == nil || presence.strict == nil {
		return errors.New("strict admission UI presence is not provisioned")
	}
	if err := presence.Observe(connection, now); err != nil {
		return err
	}
	if presence.verifyAdmission != nil {
		if err := presence.verifyAdmission(connection); err != nil {
			return err
		}
	}
	return presence.strict.observe(scope, now)
}

func (presence *uiAdmissionPresence) observe(input NativeUIScope, now time.Time) error {
	scope, err := normalizeNativeUIScope(input)
	if err != nil {
		return err
	}
	presence.mu.Lock()
	defer presence.mu.Unlock()
	if _, retired := presence.retired[scope.Epoch]; retired {
		return errors.New("retired native UI epoch")
	}
	old := presence.current
	if old.Epoch == scope.Epoch && (scope.Generation < old.Generation || scope.Generation == old.Generation && scope != old) {
		return errors.New("stale native UI login scope")
	}
	if old.Epoch != "" && old.Epoch != scope.Epoch {
		if len(presence.retired) >= 64 {
			return errors.New("native UI epoch limit")
		}
		presence.retired[old.Epoch] = struct{}{}
	}
	before := presence.login
	presence.current = scope
	switch {
	case !scope.Authenticated || scope.SessionID == "" || scope.ServerURL != presence.server || scope.UserID != presence.subject:
		presence.login = endpointUILogin{}
	case old != scope || before.Epoch == "" || now.Before(presence.observed) || now.Sub(presence.observed) >= uiPresenceTTL:
		var epoch [16]byte
		if _, err := rand.Read(epoch[:]); err != nil {
			return err
		}
		presence.login = endpointUILogin{SubjectID: scope.UserID, Epoch: hex.EncodeToString(epoch[:]), SessionID: scope.SessionID}
	}
	presence.observed = now.UTC()
	if before != presence.login {
		select {
		case presence.changed <- struct{}{}:
		default:
		}
	}
	return nil
}

func (presence *uiAdmissionPresence) snapshot(now time.Time) (*endpointUILogin, *time.Time) {
	presence.mu.Lock()
	defer presence.mu.Unlock()
	if presence.login.Epoch == "" || now.Before(presence.observed) || now.Sub(presence.observed) >= uiPresenceTTL {
		return nil, nil
	}
	login, observed := presence.login, presence.observed
	return &login, &observed
}
