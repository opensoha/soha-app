package endpointservice

import "time"

// Wire DTOs follow soha-contracts/network/network-runtime-protocol.schema.json.
type VPNManagedConnectRequest struct {
	RequestID    string `json:"requestId"`
	IntentID     string `json:"intentId"`
	IntentToken  string `json:"intentToken"`
	ProbeBatchID string `json:"probeBatchId,omitempty"`
}

type VPNProbeDescriptor struct {
	GatewayID    string     `json:"gatewayId"`
	RuntimeID    string     `json:"runtimeId"`
	Name         string     `json:"name"`
	ProviderCode string     `json:"providerCode"`
	URL          string     `json:"url,omitempty"`
	Token        string     `json:"token,omitempty"`
	ExpiresAt    *time.Time `json:"expiresAt,omitempty"`
}

type VPNManagedPrepareResult struct {
	RequestID               string               `json:"requestId"`
	IntentID                string               `json:"intentId"`
	ProfileID               string               `json:"profileId"`
	ProfileRevision         int                  `json:"profileRevision"`
	SelectionPolicyRevision int                  `json:"selectionPolicyRevision"`
	ExpiresAt               time.Time            `json:"expiresAt"`
	SamplesPerGateway       int                  `json:"samplesPerGateway"`
	TimeoutMillis           int                  `json:"timeoutMillis"`
	MaxConcurrency          int                  `json:"maxConcurrency"`
	Descriptors             []VPNProbeDescriptor `json:"descriptors"`
}

type VPNManagedConnectResult struct {
	VPNConnectResult
	ProfileID               string   `json:"profileId"`
	ProfileRevision         int      `json:"profileRevision"`
	SelectionPolicyRevision int      `json:"selectionPolicyRevision"`
	Selection               string   `json:"selection"`
	SelectionReason         string   `json:"selectionReason"`
	SiteID                  string   `json:"siteId"`
	NetworkSpaceID          string   `json:"networkSpaceId"`
	Mode                    string   `json:"mode"`
	ResourceIDs             []string `json:"resourceIds"`
	DecisionID              string   `json:"decisionId"`
	FailoverOnDisconnect    bool     `json:"failoverOnDisconnect"`
	RetryCooldownSeconds    int      `json:"retryCooldownSeconds"`
	MaxAttempts             int      `json:"maxAttempts"`
}

type VPNProbeResult struct {
	GatewayID    string    `json:"gatewayId"`
	SentCount    int       `json:"sentCount"`
	RTTSamplesMs []float64 `json:"rttSamplesMs"`
}

type VPNProbeBatch struct {
	IntentID                string           `json:"intentId"`
	ProfileID               string           `json:"profileId"`
	ProfileRevision         int              `json:"profileRevision"`
	SelectionPolicyRevision int              `json:"selectionPolicyRevision"`
	BatchID                 string           `json:"batchId"`
	NetworkEpoch            string           `json:"networkEpoch"`
	WindowStartedAt         time.Time        `json:"windowStartedAt"`
	WindowEndedAt           time.Time        `json:"windowEndedAt"`
	Results                 []VPNProbeResult `json:"results"`
}
