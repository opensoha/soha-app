package endpointservice

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
)

type EAPArtifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type EAPCleanup struct {
	RequestID      string                `json:"requestId,omitempty"`
	Certificate    *EAPCertificateResult `json:"certificate,omitempty"`
	CACertificates []string              `json:"caCertificates,omitempty"`
	Artifacts      []EAPArtifact         `json:"artifacts,omitempty"`
}

func eapCertificateHash(encoded string) string {
	certificate, err := parseEAPCertificate(encoded)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(certificate.Raw))
}

func (manager *AdmissionManager) queueCleanup(job EAPCleanup) {
	if job.Certificate != nil {
		job.CACertificates = append(slices.Clone(job.CACertificates), job.Certificate.CACertificatePEM)
	}
	if job.RequestID == "" && len(job.CACertificates) == 0 && len(job.Artifacts) == 0 {
		return
	}
	for index := range manager.state.Cleanup {
		stored := &manager.state.Cleanup[index]
		if stored.RequestID != job.RequestID {
			continue
		}
		if stored.Certificate == nil {
			stored.Certificate = job.Certificate
		}
		for _, encoded := range job.CACertificates {
			if !slices.Contains(stored.CACertificates, encoded) {
				stored.CACertificates = append(stored.CACertificates, encoded)
			}
		}
		for _, artifact := range job.Artifacts {
			if !slices.Contains(stored.Artifacts, artifact) {
				stored.Artifacts = append(stored.Artifacts, artifact)
			}
		}
		return
	}
	manager.state.Cleanup = append(manager.state.Cleanup, job)
}

func (manager *AdmissionManager) detachSelection(index int) {
	selection := manager.state.Selections[index]
	job := EAPCleanup{CACertificates: slices.Clone(selection.Profile.CACertificates)}
	if selection.ArtifactPath != "" {
		job.Artifacts = []EAPArtifact{{Path: selection.ArtifactPath, SHA256: selection.ArtifactSHA256}}
	}
	manager.queueCleanup(job)
	manager.state.Selections = slices.Delete(manager.state.Selections, index, index+1)
	if len(manager.state.Selections) == 0 {
		for _, identity := range []*eapIdentity{manager.state.Active, manager.state.Pending} {
			if identity != nil {
				manager.queueCleanup(EAPCleanup{RequestID: identity.RequestID, Certificate: identity.Certificate})
			}
		}
		manager.state.Active, manager.state.Pending = nil, nil
	}
}

func (manager *AdmissionManager) cleanup(ctx context.Context) error {
	retained := map[string]bool{}
	for _, selection := range manager.state.Selections {
		for _, encoded := range selection.Profile.CACertificates {
			retained[eapCertificateHash(encoded)] = true
		}
	}
	for _, identity := range []*eapIdentity{manager.state.Active, manager.state.Pending} {
		if identity != nil && identity.Certificate != nil {
			retained[eapCertificateHash(identity.Certificate.CACertificatePEM)] = true
		}
	}
	for index := len(manager.state.Cleanup) - 1; index >= 0; index-- {
		job := manager.state.Cleanup[index]
		job.CACertificates = slices.DeleteFunc(slices.Clone(job.CACertificates), func(encoded string) bool {
			return retained[eapCertificateHash(encoded)]
		})
		if err := manager.system.Cleanup(ctx, job); err != nil {
			manager.diagnostic = "cleanup_retry_pending"
			return err
		}
		manager.state.Cleanup = slices.Delete(manager.state.Cleanup, index, index+1)
		if err := manager.save(); err != nil {
			return err
		}
	}
	return nil
}

func (manager *AdmissionManager) recoverArtifacts(ctx context.Context) error {
	retained := make([]EAPArtifact, 0, len(manager.state.Selections))
	for _, selection := range manager.state.Selections {
		if selection.ArtifactPath != "" {
			retained = append(retained, EAPArtifact{Path: selection.ArtifactPath, SHA256: selection.ArtifactSHA256})
		}
	}
	if err := manager.system.RecoverArtifacts(ctx, retained); err != nil {
		if manager.diagnostic == "" {
			manager.diagnostic = "cleanup_retry_pending"
		}
		return err
	}
	return nil
}
