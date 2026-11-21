package endpointservice

import (
	"net"
	"testing"
	"time"
)

func TestStrictAdmissionUIScopeRequiresVerifiedBoundLogin(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	verified := false
	activeConsole := true
	presence := &UIProcessPresence{verify: func(net.Conn) error {
		verified = true
		return nil
	}, verifyAdmission: func(net.Conn) error {
		if !activeConsole {
			return net.ErrClosed
		}
		return nil
	}}
	err := presence.ConfigureAdmissionLease(Config{
		StrictAdmissionUILease: true, NativeUIServerURL: "https://org.example.test", NativeUIUserID: "user-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := NativeUIScope{ServerURL: "https://org.example.test", UserID: "user-1", SessionID: "active-session", Epoch: "native-ui-scope-1", Generation: 1, Authenticated: true}
	if err := presence.observeAdmissionScope(nil, scope, now); err != nil || !verified {
		t.Fatalf("unverified scope: %v", err)
	}
	initial, _ := presence.strict.snapshot(now)
	if initial == nil {
		t.Fatal("bound UI did not acquire a login proof")
	}
	if err := presence.observeAdmissionScope(nil, scope, now.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	renewed, _ := presence.strict.snapshot(now.Add(11 * time.Second))
	if renewed == nil || renewed.Epoch != initial.Epoch {
		t.Fatal("ordinary renewal changed the login epoch")
	}
	activeConsole = false
	if err := presence.observeAdmissionScope(nil, scope, now.Add(20*time.Second)); err == nil {
		t.Fatal("inactive desktop could refresh the lease")
	}
	activeConsole = true
	if expired, _ := presence.strict.snapshot(now.Add(40 * time.Second)); expired != nil {
		t.Fatal("expired scope still proves UI presence")
	}
	if err := presence.observeAdmissionScope(nil, scope, now.Add(41*time.Second)); err != nil {
		t.Fatal(err)
	}
	woke, _ := presence.strict.snapshot(now.Add(41 * time.Second))
	if woke == nil || woke.Epoch == initial.Epoch {
		t.Fatal("wake reused an expired login epoch")
	}
	other := scope
	other.Generation++
	other.UserID = "different-user"
	if err := presence.observeAdmissionScope(nil, other, now.Add(42*time.Second)); err != nil {
		t.Fatal(err)
	}
	if proof, _ := presence.strict.snapshot(now.Add(42 * time.Second)); proof != nil {
		t.Fatal("a different user's scope retained the login proof")
	}
	if err := presence.observeAdmissionScope(nil, scope, now.Add(43*time.Second)); err == nil {
		t.Fatal("the retired login generation restored the lease")
	}
	other.Generation++
	other.UserID, other.SessionID = scope.UserID, ""
	if err := presence.observeAdmissionScope(nil, other, now.Add(44*time.Second)); err != nil {
		t.Fatal(err)
	}
	if proof, _ := presence.strict.snapshot(now.Add(44 * time.Second)); proof != nil {
		t.Fatal("a login without a Core session acquired a lease")
	}
}
