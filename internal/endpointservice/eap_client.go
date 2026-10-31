package endpointservice

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

type RuntimeHTTPError struct {
	StatusCode int
	Code       string
}

func (err *RuntimeHTTPError) Error() string {
	return fmt.Sprintf("network runtime returned HTTP %d", err.StatusCode)
}

var ErrEAPCertificateStale = errors.New("EAP certificate activation window expired or the parent credential changed")

func (client *ControlClient) IssueEAPCertificate(ctx context.Context, payload EAPCertificateRequest, deviceID, subjectID string) (EAPCertificateResult, error) {
	if !identifierPattern.MatchString(payload.RequestID) || !identifierPattern.MatchString(deviceID) || !identifierPattern.MatchString(subjectID) || len(payload.CSRPEM) > 4096 {
		return EAPCertificateResult{}, errors.New("EAP certificate request is invalid")
	}
	if _, err := parseEAPCSR(payload.CSRPEM); err != nil {
		return EAPCertificateResult{}, err
	}
	raw, err := client.runtimeMessage(MessageEAPCertificateRequest, payload)
	if err != nil {
		return EAPCertificateResult{}, err
	}
	message, err := client.postMessage(ctx, client.runtimeURL("eap:certificate"), raw, "", http.StatusOK)
	if err != nil {
		if eapStaleResponse(err) {
			return EAPCertificateResult{}, ErrEAPCertificateStale
		}
		return EAPCertificateResult{}, err
	}
	var result EAPCertificateResult
	if err := client.decodeResponse(message, MessageEAPCertificateResult, &result); err != nil || !identifierPattern.MatchString(result.CredentialID) || result.Status != "pending" && result.Status != "active" || !validReadbackHash(result.Fingerprint) || !result.ExpiresAt.After(client.now()) {
		return EAPCertificateResult{}, errors.New("network control returned an invalid EAP certificate")
	}
	if err := validateEAPCertificate(result, payload.CSRPEM, deviceID, subjectID, client.now()); err != nil {
		return EAPCertificateResult{}, err
	}
	return result, nil
}

func (client *ControlClient) ActivateEAPCertificate(ctx context.Context, payload EAPCertificateActivateRequest) (EAPCertificateActivateResult, error) {
	if !identifierPattern.MatchString(payload.CredentialID) || !validReadbackHash(payload.Fingerprint) {
		return EAPCertificateActivateResult{}, errors.New("EAP activation request is invalid")
	}
	raw, err := client.runtimeMessage(MessageEAPCertificateActivateRequest, payload)
	if err != nil {
		return EAPCertificateActivateResult{}, err
	}
	message, err := client.postMessage(ctx, client.runtimeURL("eap:activate"), raw, "", http.StatusOK)
	if err != nil {
		if eapStaleResponse(err) {
			return EAPCertificateActivateResult{}, ErrEAPCertificateStale
		}
		return EAPCertificateActivateResult{}, err
	}
	var result EAPCertificateActivateResult
	if err := client.decodeResponse(message, MessageEAPCertificateActivateResult, &result); err != nil || result.Status != "active" || result.CredentialID != payload.CredentialID || result.Fingerprint != payload.Fingerprint || !result.ExpiresAt.After(client.now()) {
		return EAPCertificateActivateResult{}, errors.New("network control returned an invalid EAP activation")
	}
	return result, nil
}

func eapStaleResponse(err error) bool {
	var responseError *RuntimeHTTPError
	return errors.As(err, &responseError) && responseError.StatusCode == http.StatusConflict && responseError.Code == "eap_certificate_stale"
}
