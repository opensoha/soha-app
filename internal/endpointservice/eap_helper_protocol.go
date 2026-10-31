package endpointservice

type eapUserRequest struct {
	Action      string                `json:"action"`
	DeviceID    string                `json:"deviceId"`
	RequestID   string                `json:"requestId,omitempty"`
	ExpectedSID string                `json:"expectedSid"`
	Profile     *AdmissionProfile     `json:"profile,omitempty"`
	Certificate *EAPCertificateResult `json:"certificate,omitempty"`
	Adapter     *EAPAdapter           `json:"adapter,omitempty"`
	ExpectedXML []byte                `json:"expectedXml,omitempty"`
	Cleanup     *EAPCleanup           `json:"cleanup,omitempty"`
}

type eapUserResponse struct {
	OK          bool   `json:"ok"`
	CSR         string `json:"csr,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	ProfileXML  []byte `json:"profileXml,omitempty"`
	Present     bool   `json:"present,omitempty"`
}
