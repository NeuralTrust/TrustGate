package upstream

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/gcp"
)

func buildTargetAuth(saService gcp.ServiceAccountService, idx int, auth *request.TargetAuthRequest) (*upstream.TargetAuth, error) {
	switch auth.Type {
	case request.AuthTypeOAuth2:
		if auth.OAuth == nil {
			return nil, fmt.Errorf("%w: target %d: auth.oauth is required", domain.ErrValidation, idx)
		}
		return upstream.NewOAuth2Auth(buildOAuthConfig(auth.OAuth)), nil
	case request.AuthTypeGCPServiceAccount:
		saBase64 := ""
		if auth.GCPServiceAccount != nil {
			saBase64 = *auth.GCPServiceAccount
		}
		if saBase64 == "" {
			resolved, err := saService.ResolveSAFromEnv()
			if err != nil {
				return nil, fmt.Errorf("%w: target %d: gcp_service_account not provided and fallback failed: %v", domain.ErrValidation, idx, err)
			}
			saBase64 = resolved
		}
		if err := saService.ValidateSA(saBase64); err != nil {
			return nil, fmt.Errorf("%w: target %d: invalid service account: %v", domain.ErrValidation, idx, err)
		}
		encrypted, err := saService.EncryptSA(saBase64)
		if err != nil {
			return nil, fmt.Errorf("target %d: failed to encrypt service account: %w", idx, err)
		}
		return upstream.NewGCPServiceAccountAuth(encrypted), nil
	default:
		return nil, fmt.Errorf("%w: target %d: unsupported auth.type: %s", domain.ErrValidation, idx, auth.Type)
	}
}

func buildOAuthConfig(o *request.UpstreamOAuthRequest) *upstream.TargetOAuthConfig {
	return &upstream.TargetOAuthConfig{
		TokenURL:     o.TokenURL,
		GrantType:    o.GrantType,
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		UseBasicAuth: o.UseBasicAuth,
		Scopes:       o.Scopes,
		Audience:     o.Audience,
		Code:         o.Code,
		RedirectURI:  o.RedirectURI,
		CodeVerifier: o.CodeVerifier,
		RefreshToken: o.RefreshToken,
		Username:     o.Username,
		Password:     o.Password,
		Extra:        o.Extra,
	}
}
