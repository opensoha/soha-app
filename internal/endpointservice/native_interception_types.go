package endpointservice

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// InterceptionIntent contains only user intent; the service chooses every OS target.
type InterceptionIntent struct {
	RequestID          string `json:"requestId"`
	ExpectedGeneration uint64 `json:"expectedGeneration"`
	SystemProxy        bool   `json:"systemProxy"`
	TUN                bool   `json:"tun"`
}

type InterceptionCapabilities struct {
	SystemProxy bool   `json:"systemProxy"`
	TUN         bool   `json:"tun"`
	ReasonCode  string `json:"reasonCode,omitempty"`
}

type InterceptionImpact struct {
	SystemProxyScope string `json:"systemProxyScope,omitempty"`
	NetworkService   string `json:"networkService,omitempty"`
	IPv4             bool   `json:"ipv4"`
	IPv6             bool   `json:"ipv6"`
	DNS              bool   `json:"dns"`
}

type InterceptionStatus struct {
	Generation         uint64                   `json:"generation"`
	DesiredSystemProxy bool                     `json:"desiredSystemProxy"`
	DesiredTUN         bool                     `json:"desiredTUN"`
	SystemProxy        bool                     `json:"systemProxy"`
	TUN                bool                     `json:"tun"`
	State              string                   `json:"state"`
	ReasonCode         string                   `json:"reasonCode,omitempty"`
	CleanupPending     bool                     `json:"cleanupPending"`
	ObservedAt         time.Time                `json:"observedAt"`
	Capabilities       InterceptionCapabilities `json:"capabilities"`
	Impact             InterceptionImpact       `json:"impact"`
}

const (
	nativeMaxCapturePrefixes   = 512
	interceptionInactive       = "inactive"
	interceptionPreparing      = "preparing"
	interceptionActive         = "active"
	interceptionStopping       = "stopping"
	interceptionSuspended      = "suspended"
	interceptionCleanupPending = "cleanup_pending"
	interceptionFailed         = "failed"
)

type nativeOwner struct {
	UserID    string `json:"userId"`
	SessionID string `json:"sessionId"`
}

// NativePeer is authenticated from the connection and never decoded from IPC.
type NativePeer struct {
	owner   nativeOwner
	pid     uint32
	session nativeSession
}

type nativeSession interface {
	Owner() nativeOwner
	Validate(context.Context, bool) error // true permits restoration only.
	Close() error
}

type nativeInterface struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Index     uint32         `json:"index"`
	Kind      string         `json:"kind"` // physical, tunnel, loopback, unknown.
	Addresses []netip.Prefix `json:"addresses,omitempty"`
}

type nativeRoute struct {
	Destination netip.Prefix    `json:"destination"`
	Gateway     netip.Addr      `json:"gateway"`
	Interface   nativeInterface `json:"interface"`
	Metric      uint32          `json:"metric"`
	Flags       uint32          `json:"flags"`
}

type nativeResolverScope struct {
	ID        string          `json:"id"`
	Interface nativeInterface `json:"interface"`
	Domains   []string        `json:"domains,omitempty"`
	Default   bool            `json:"default"`
	Priority  uint32          `json:"priority"`
	Servers   []netip.Addr    `json:"servers"`
}

type nativeDNSConfig struct {
	Automatic bool         `json:"automatic"`
	Servers   []netip.Addr `json:"servers,omitempty"`
}

type nativeScope struct {
	ServiceID string          `json:"serviceId,omitempty"`
	Interface nativeInterface `json:"interface"`
	Family    uint8           `json:"family,omitempty"`
}

type nativeProxyValue struct {
	Bool    bool     `json:"bool,omitempty"`
	Number  uint32   `json:"number,omitempty"`
	Text    string   `json:"text,omitempty"`
	Strings []string `json:"strings,omitempty"`
}

// Only the branch selected by the fixed change kind is valid.
type nativeValue struct {
	Present bool              `json:"present"`
	Route   *nativeRoute      `json:"route,omitempty"`
	DNS     *nativeDNSConfig  `json:"dns,omitempty"`
	Proxy   *nativeProxyValue `json:"proxy,omitempty"`
}

type nativeChange struct {
	ID     string      `json:"id"`
	Kind   string      `json:"kind"` // route, dns, proxy.
	Scope  nativeScope `json:"scope"`
	Field  string      `json:"field,omitempty"` // Platform-validated fixed proxy property only.
	Before nativeValue `json:"before"`
	After  nativeValue `json:"after"`
}

type nativeReceipt struct {
	ChangeID string
	Outcome  string // applied, not_applied, conflict, unknown.
	Current  nativeValue
}

type nativeSnapshot struct {
	Generation         uint64
	Interfaces         []nativeInterface
	Routes             []nativeRoute
	Resolvers          []nativeResolverScope
	Settings           []nativeChange // Before only; the platform planner fills After.
	PrimaryServiceID   string
	PrimaryServiceName string
}

// The common planner supplies these fixed targets; no renderer parameters enter it.
type nativeInterceptionPlan struct {
	SystemProxy     bool
	TUN             bool
	ProxyEndpoint   netip.AddrPort
	DNSServers      []netip.Addr
	TUNInterface    nativeInterface
	CapturePrefixes []netip.Prefix
	ExclusionRoutes []nativeRoute
}

type nativeExit struct {
	Route      nativeRoute
	Generation uint64
	Interface  nativeInterface
	Source     netip.Addr
	Gateway    netip.Addr
	ViaWG      bool
}

type nativePlatform interface {
	Authenticate(context.Context, net.Conn) (NativePeer, error)
	AcquireRestoreSession(context.Context, nativeOwner) (nativeSession, error)
	Snapshot(context.Context, nativeSession) (nativeSnapshot, error)
	PlanChanges(nativeSnapshot, nativeInterceptionPlan) ([]nativeChange, error)
	ReadChange(context.Context, nativeSession, nativeChange) (nativeValue, error)
	CompareApply(context.Context, nativeSession, nativeChange) (nativeReceipt, error)
	CompareRestore(context.Context, nativeSession, nativeChange) (nativeReceipt, error)
	SelectExit(context.Context, netip.Addr, nativeSnapshot, TunnelReadback) (nativeExit, error)
	Control(nativeExit) func(string, string, syscall.RawConn) error
	VerifyListenerOwner(context.Context, nativeSession, string, netip.AddrPort, uint32) error
	FlushResolverCache(context.Context, nativeSession) error
}

// Only the existing WG owner may delegate its own verified DNS handle. The
// before/after values contain no key material; After is fixed owned loopback DNS.
// CompareNativeDNS(..., true) alone may return "absent", and only after proving
// the exact journaled WG interface/handle no longer exists. Never target a new one.
type nativeWGDNSOwner interface {
	PrepareNativeDNS(context.Context, nativeSession, []netip.Addr) ([]nativeChange, error)
	ReadNativeDNS(context.Context, nativeSession, nativeChange) (nativeValue, error)
	CompareNativeDNS(context.Context, nativeSession, nativeChange, bool) (nativeReceipt, error)
	ReleaseNativeDNS(context.Context, nativeSession, []nativeChange) error
}

// The original public readback retains its hostname. Native routing needs the
// actual numeric peer from the same verified WG incarnation, without new DNS.
type nativeWGPeerReader interface {
	NativePeerEndpoint(context.Context, nativeSession) (netip.AddrPort, error)
}

// Proof comes only from the current owned exec.Cmd, not configuration or IPC.
// Arguments contain the fixed executable/-d/-f paths, never configuration data.
type nativeOwnedProcessProof struct {
	PID             uint32   `json:"pid"`
	ProcessEpoch    string   `json:"processEpoch"`
	BinarySHA256    string   `json:"binarySha256"`
	ExecutablePath  string   `json:"executablePath"`
	LaunchDirectory string   `json:"launchDirectory"`
	Arguments       []string `json:"arguments"`
}

type nativeOwnedProcessIdentity struct {
	Proof       nativeOwnedProcessProof `json:"proof"`
	Incarnation string                  `json:"incarnation"` // Exact OS PID-version/start identity.
}

// Optional Darwin crash recovery. Recover returns stopped/gone only after
// verifying the exact old incarnation; it never signals a reused PID.
type nativeOwnedProcessRecovery interface {
	CaptureOwnedProcess(context.Context, nativeSession, nativeOwnedProcessProof) (nativeOwnedProcessIdentity, error)
	RecoverOwnedProcess(context.Context, nativeSession, nativeOwnedProcessIdentity) (string, error)
}

type guardedEgress interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
	DialContext(context.Context, string, string) (net.Conn, error)
	DialPinned(context.Context, string, netip.AddrPort) (net.Conn, error)
}
