package endpointservice

import (
	"context"
	"errors"
)

type EAPPasswordSystem interface {
	PasswordSupport(context.Context, AdmissionProfile) (bool, string)
	StagePassword(context.Context, string, AdmissionProfile, EAPAdapter) (EAPStagedProfile, error)
	ReadbackPassword(context.Context, string, AdmissionProfile, EAPAdapter) error
	ConnectPassword(context.Context, string, AdmissionProfile, EAPAdapter, []byte) error
}

func admissionMethod(p AdmissionProfile) string {
	if p.EAPMethod == "" {
		return "tls"
	}
	return p.EAPMethod
}
func validateEAPPassword(p string) error {
	if len(p) == 0 || len(p) > 72 {
		return errors.New("EAP password is invalid")
	}
	return nil
}
func (m *AdmissionManager) methodSupport(ctx context.Context, p AdmissionProfile) (bool, string) {
	if admissionMethod(p) == "tls" {
		if system, ok := m.system.(interface {
			TLSSupport(context.Context, AdmissionProfile) (bool, string)
		}); ok {
			return system.TLSSupport(ctx, p)
		}
		return true, ""
	}
	if admissionMethod(p) != "ttls" || p.InnerMethod != "pap" {
		return false, "eap_method_unsupported"
	}
	if system, ok := m.system.(EAPPasswordSystem); ok {
		return system.PasswordSupport(ctx, p)
	}
	return false, "native_password_api_unavailable"
}

var ErrEAPSystemInteractionRequired = errors.New("complete EAP authentication in the trusted system network interface")

func credentialInteraction(system EAPSystem, p AdmissionProfile) string {
	if admissionMethod(p) != "ttls" {
		return ""
	}
	if native, ok := system.(interface{ CredentialInteraction(AdmissionProfile) string }); ok {
		return native.CredentialInteraction(p)
	}
	return "app-input"
}
