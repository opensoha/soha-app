//go:build windows

package endpointservice

import (
	"context"
	"crypto/ecdsa"
	"errors"
)

func (system *WindowsEAPSystem) Cleanup(ctx context.Context, job EAPCleanup) error {
	if len(job.Artifacts) != 0 {
		return errors.New("Windows EAP cleanup has unexpected exported files")
	}
	_, err := callEAPUserHelper(ctx, system.userSID, eapUserRequest{Action: "cleanup", DeviceID: system.deviceID, RequestID: job.RequestID, Cleanup: &job})
	return err
}

func (*WindowsEAPSystem) RecoverArtifacts(context.Context, []EAPArtifact) error { return nil }

func cleanupWindowsEAPUser(deviceID string, job EAPCleanup) error {
	if len(job.Artifacts) != 0 || job.RequestID != "" && !identifierPattern.MatchString(job.RequestID) || job.RequestID == "" && job.Certificate != nil || len(job.CACertificates) > 64 {
		return errors.New("Windows EAP cleanup reference is invalid")
	}
	if job.RequestID != "" {
		key, err := openEAPCNGKey(deviceID, job.RequestID, false)
		missing := err == eapCNGStatus(0x80090016) || err == eapCNGStatus(0x80090011)
		if err != nil && !missing {
			return err
		}
		if key != nil {
			defer key.Close()
		}
		if job.Certificate != nil {
			leaf, err := parseEAPCertificate(job.Certificate.CertificatePEM)
			if err != nil {
				return err
			}
			if key != nil {
				public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
				if !ok || !key.public.Equal(public) {
					return errors.New("obsolete EAP certificate does not match its CNG key")
				}
			}
			if err := removeOwnedEAPUserCertificate("MY", leaf, deviceID); err != nil {
				return err
			}
		}
		if key != nil {
			if err := callEAPCNG(eapNCryptDelete, key.key, 0x40); err != nil {
				return err
			}
			key.key = 0
		}
	}
	for _, encoded := range job.CACertificates {
		certificate, err := parseEAPCertificate(encoded)
		if err != nil || !certificate.IsCA {
			return errors.New("obsolete EAP trust certificate is invalid")
		}
		for _, store := range []string{"CA", "ROOT"} {
			if err := removeOwnedEAPUserCertificate(store, certificate, deviceID); err != nil {
				return err
			}
		}
	}
	return nil
}
