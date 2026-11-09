package endpointservice

import "time"

const (
	MessageEAPCertificateRequest         = "eap.certificate.request"
	MessageEAPCertificateResult          = "eap.certificate.result"
	MessageEAPCertificateActivateRequest = "eap.certificate.activate.request"
	MessageEAPCertificateActivateResult  = "eap.certificate.activate.result"
)

type EAPCertificateRequest struct {
	RequestID string `json:"requestId"`
	CSRPEM    string `json:"csrPem"`
}

type EAPCertificateResult struct {
	CredentialID     string    `json:"credentialId"`
	CertificatePEM   string    `json:"certificatePem"`
	CACertificatePEM string    `json:"caCertificatePem"`
	Fingerprint      string    `json:"fingerprint"`
	ExpiresAt        time.Time `json:"expiresAt"`
	Status           string    `json:"status"`
}

type EAPCertificateActivateRequest struct {
	CredentialID    string `json:"credentialId"`
	Fingerprint     string `json:"fingerprint"`
	RequestID       string `json:"requestId,omitempty"`
	ProfileID       string `json:"profileId,omitempty"`
	ProfileRevision string `json:"profileRevision,omitempty"`
}

type EAPCertificateActivateResult struct {
	CredentialID string    `json:"credentialId"`
	Fingerprint  string    `json:"fingerprint"`
	ExpiresAt    time.Time `json:"expiresAt"`
	Status       string    `json:"status"`
}

type AdmissionConfiguration struct {
	Profiles         []AdmissionProfile `json:"profiles"`
	RestrictionEpoch int                `json:"restrictionEpoch"`
}

type AdmissionProfile struct {
	ID                           string   `json:"id"`
	EAPMethod                    string   `json:"eapMethod,omitempty"`
	InnerMethod                  string   `json:"innerMethod,omitempty"`
	CredentialSource             string   `json:"credentialSource,omitempty"`
	ProfileRevision              string   `json:"profileRevision,omitempty"`
	SiteID                       string   `json:"siteId"`
	AccessMedium                 string   `json:"accessMedium"`
	SSID                         string   `json:"ssid,omitempty"`
	Identity                     string   `json:"identity"`
	ServerNames                  []string `json:"serverNames"`
	CACertificates               []string `json:"caCertificates"`
	WifiSecurity                 string   `json:"wifiSecurity"`
	ClientCertificateFingerprint string   `json:"clientCertificateFingerprint,omitempty"`
}

type EAPCertificateRevokeRequest struct {
	RequestID    string `json:"requestId"`
	CredentialID string `json:"credentialId"`
	Fingerprint  string `json:"fingerprint"`
	ReasonCode   string `json:"reasonCode"`
}
type EAPCertificateRevokeResult struct {
	RequestID    string `json:"requestId"`
	CredentialID string `json:"credentialId"`
	Fingerprint  string `json:"fingerprint"`
	Status       string `json:"status"`
}
