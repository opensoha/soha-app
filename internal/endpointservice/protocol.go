package endpointservice

import (
	"encoding/json"
	"time"
)

const (
	RuntimeSchemaVersion          = "network-runtime/v1alpha1"
	IngestSchemaVersion           = "network-ingest/v1alpha1"
	defaultRuntimeIntervalSeconds = 60
	minRuntimeIntervalSeconds     = 30
	maxRuntimeIntervalSeconds     = 300

	MessageEnrollmentRequest  = "runtime.enroll.request"
	MessageEnrollmentResult   = "runtime.enroll.result"
	MessageConfiguration      = "configuration.desired"
	MessageConfigurationApply = "configuration.applied"
	MessageLeaseRenewRequest  = "lease.renew.request"
	MessageLeaseRenewResult   = "lease.renew.result"
	MessageLeaseRevoke        = "lease.revoke"
	MessageVPNConnectRequest  = "vpn.connect.request"
	MessageVPNConnectResult   = "vpn.connect.result"
)

// These wire DTOs mirror soha-contracts/network/network-runtime-protocol.schema.json.
// The independent App must not import soha/internal packages.
type RuntimeMessage struct {
	SchemaVersion string          `json:"schemaVersion"`
	MessageID     string          `json:"messageId"`
	MessageType   string          `json:"messageType"`
	ProducerID    string          `json:"producerId"`
	RuntimeID     string          `json:"runtimeId"`
	RuntimeKind   string          `json:"runtimeKind"`
	OccurredAt    time.Time       `json:"occurredAt"`
	ExpiresAt     time.Time       `json:"expiresAt"`
	Payload       json.RawMessage `json:"payload"`
}

type EnrollmentRequest struct {
	EnrollmentID       string   `json:"enrollmentId"`
	ChallengeID        string   `json:"challengeId"`
	DeviceID           string   `json:"deviceId"`
	DevicePublicKey    string   `json:"devicePublicKey"`
	WireGuardPublicKey string   `json:"wireguardPublicKey"`
	Platform           string   `json:"platform"`
	ClientVersion      string   `json:"clientVersion"`
	Capabilities       []string `json:"capabilities"`
}

type EnrollmentResult struct {
	Accepted            bool       `json:"accepted"`
	ReasonCode          string     `json:"reasonCode"`
	CredentialReference string     `json:"credentialReference,omitempty"`
	CredentialExpiresAt *time.Time `json:"credentialExpiresAt,omitempty"`
}

type NetworkLease struct {
	ID             string    `json:"id"`
	SessionID      string    `json:"sessionId"`
	SubjectID      string    `json:"subjectId"`
	DeviceID       string    `json:"deviceId"`
	NetworkSpaceID string    `json:"networkSpaceId"`
	CIDRs          []string  `json:"cidrs"`
	PolicyVersion  int       `json:"policyVersion"`
	IssuedAt       time.Time `json:"issuedAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type ResourceLease struct {
	ID            string    `json:"id"`
	SessionID     string    `json:"sessionId"`
	SubjectID     string    `json:"subjectId"`
	DeviceID      string    `json:"deviceId"`
	ResourceIDs   []string  `json:"resourceIds"`
	PolicyVersion int       `json:"policyVersion"`
	IssuedAt      time.Time `json:"issuedAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

type ConfigurationDesired struct {
	ConfigurationVersion int                     `json:"configurationVersion"`
	PolicyVersion        int                     `json:"policyVersion"`
	ValidUntil           time.Time               `json:"validUntil"`
	AccessProfile        string                  `json:"accessProfile"`
	ProtectedResourceIDs []string                `json:"protectedResourceIds"`
	NetworkLeases        []NetworkLease          `json:"networkLeases"`
	ResourceLeases       []ResourceLease         `json:"resourceLeases"`
	RuntimeIntervals     *RuntimeIntervals       `json:"runtimeIntervals,omitempty"`
	WireGuard            *WireGuardConfiguration `json:"wireguard,omitempty"`
	Mihomo               *MihomoConfiguration    `json:"mihomo,omitempty"`
}

type RuntimeIntervals struct {
	HeartbeatIntervalSeconds         int `json:"heartbeatIntervalSeconds"`
	ConfigurationPollIntervalSeconds int `json:"configurationPollIntervalSeconds"`
}

type MihomoConfiguration struct {
	Mode            string   `json:"mode"`
	SourceType      string   `json:"sourceType,omitempty"`
	ProfileID       string   `json:"profileId"`
	ProfileRevision int      `json:"profileRevision"`
	MixedPort       int      `json:"mixedPort"`
	ControllerPort  int      `json:"controllerPort"`
	DNSMode         string   `json:"dnsMode"`
	FakeIPRange     string   `json:"fakeIpRange,omitempty"`
	SelectorGroup   string   `json:"selectorGroup"`
	SelectedProxy   string   `json:"selectedProxy,omitempty"`
	BypassCIDRs     []string `json:"bypassCidrs"`
	BypassHosts     []string `json:"bypassHosts"`
	FailClosed      bool     `json:"failClosed"`

	// Source secrets are fetched over the runtime's mTLS channel and never serialized.
	SubscriptionURL string            `json:"-"`
	ManualNode      *MihomoManualNode `json:"-"`
}

type MihomoManualNode struct {
	Protocol string `json:"protocol"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type MihomoSource struct {
	ProfileID       string            `json:"profileId"`
	ProfileRevision int               `json:"profileRevision"`
	SourceType      string            `json:"sourceType"`
	SubscriptionURL string            `json:"subscriptionUrl,omitempty"`
	ManualNode      *MihomoManualNode `json:"manualNode,omitempty"`
}

type MihomoSubscription struct {
	ProfileID       string `json:"profileId"`
	ProfileRevision int    `json:"profileRevision"`
	SubscriptionURL string `json:"subscriptionUrl"`
}

type WireGuardPeer struct {
	RuntimeID                  string   `json:"runtimeId"`
	DeviceID                   string   `json:"deviceId,omitempty"`
	PublicKey                  string   `json:"publicKey"`
	EndpointHost               string   `json:"endpointHost,omitempty"`
	EndpointPort               int      `json:"endpointPort,omitempty"`
	AllowedIPs                 []string `json:"allowedIPs"`
	PersistentKeepaliveSeconds int      `json:"persistentKeepaliveSeconds"`
}

type WireGuardFirewallRule struct {
	ID              string     `json:"id"`
	Effect          string     `json:"effect"`
	LeaseID         string     `json:"leaseId,omitempty"`
	SourceCIDR      string     `json:"sourceCidr"`
	DestinationCIDR string     `json:"destinationCidr"`
	Protocol        string     `json:"protocol"`
	Ports           []int      `json:"ports,omitempty"`
	ExpiresAt       *time.Time `json:"expiresAt,omitempty"`
}

type WireGuardConfiguration struct {
	Role            string                  `json:"role"`
	InterfaceName   string                  `json:"interfaceName"`
	PublicKey       string                  `json:"publicKey"`
	Addresses       []string                `json:"addresses"`
	ListenPort      int                     `json:"listenPort,omitempty"`
	MTU             int                     `json:"mtu"`
	RoutingMode     string                  `json:"routingMode"`
	FirewallDefault string                  `json:"firewallDefault"`
	Peers           []WireGuardPeer         `json:"peers"`
	Routes          []string                `json:"routes"`
	DNSServers      []string                `json:"dnsServers,omitempty"`
	FirewallRules   []WireGuardFirewallRule `json:"firewallRules"`
}

type ConfigurationApplied struct {
	ConfigurationVersion int    `json:"configurationVersion"`
	PolicyVersion        int    `json:"policyVersion"`
	Status               string `json:"status"`
	ReadbackHash         string `json:"readbackHash"`
	ReasonCode           string `json:"reasonCode,omitempty"`
}

type LeaseRenewRequest struct {
	SessionID                    string   `json:"sessionId"`
	LeaseIDs                     []string `json:"leaseIds"`
	ObservedConfigurationVersion int      `json:"observedConfigurationVersion"`
	PostureVersion               *int     `json:"postureVersion,omitempty"`
}

type LeaseRenewResult struct {
	PolicyVersion   int             `json:"policyVersion"`
	ValidUntil      time.Time       `json:"validUntil"`
	NetworkLeases   []NetworkLease  `json:"networkLeases"`
	ResourceLeases  []ResourceLease `json:"resourceLeases"`
	RevokedLeaseIDs []string        `json:"revokedLeaseIds"`
}

type LeaseRevoke struct {
	SessionID   string    `json:"sessionId"`
	LeaseIDs    []string  `json:"leaseIds"`
	ReasonCode  string    `json:"reasonCode"`
	EffectiveAt time.Time `json:"effectiveAt"`
}

type VPNConnectRequest struct {
	RequestID        string   `json:"requestId"`
	SiteID           string   `json:"siteId"`
	NetworkSpaceID   string   `json:"networkSpaceId"`
	GatewayID        string   `json:"gatewayId,omitempty"`
	Mode             string   `json:"mode"`
	ResourceIDs      []string `json:"resourceIds,omitempty"`
	AccessGrantID    string   `json:"accessGrantId,omitempty"`
	AccessGrantToken string   `json:"accessGrantToken,omitempty"`
}

type VPNConnectResult struct {
	RequestID            string          `json:"requestId"`
	Decision             string          `json:"decision"`
	ReasonCode           string          `json:"reasonCode"`
	SessionID            string          `json:"sessionId,omitempty"`
	GatewayID            string          `json:"gatewayId,omitempty"`
	ConfigurationVersion int             `json:"configurationVersion,omitempty"`
	PolicyVersion        int             `json:"policyVersion"`
	ValidUntil           time.Time       `json:"validUntil"`
	NetworkLeases        []NetworkLease  `json:"networkLeases"`
	ResourceLeases       []ResourceLease `json:"resourceLeases"`
}

type IngestBatch struct {
	SchemaVersion string        `json:"schemaVersion"`
	BatchID       string        `json:"batchId"`
	ProducerID    string        `json:"producerId"`
	ProducerKind  string        `json:"producerKind"`
	SentAt        time.Time     `json:"sentAt"`
	Events        []IngestEvent `json:"events"`
}

type IngestEvent struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Sequence   int64           `json:"sequence"`
	OccurredAt time.Time       `json:"occurredAt"`
	Payload    json.RawMessage `json:"payload"`
}
