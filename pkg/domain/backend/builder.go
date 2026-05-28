package backend

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type CreateParams struct {
	GatewayID       uuid.UUID
	Name            string
	Algorithm       string
	Targets         Targets
	EmbeddingConfig *EmbeddingConfig
	HealthChecks    *HealthChecks
}

func New(params CreateParams) (*Backend, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("backend: generate uuid: %w", err)
	}
	now := time.Now().UTC()
	b := &Backend{
		ID:              id,
		GatewayID:       params.GatewayID,
		Name:            params.Name,
		Algorithm:       params.Algorithm,
		Targets:         params.Targets,
		EmbeddingConfig: params.EmbeddingConfig,
		HealthChecks:    params.HealthChecks,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return b, nil
}

// NewAPIKeyAuth builds a TargetAuth for the common bearer-key case.
func NewAPIKeyAuth(apiKey string) *TargetAuth {
	return &TargetAuth{
		Type:   AuthTypeAPIKey,
		APIKey: &APIKeyAuth{APIKey: apiKey},
	}
}

func NewOAuth2Auth(config *TargetOAuthConfig) *TargetAuth {
	return &TargetAuth{
		Type:  AuthTypeOAuth2,
		OAuth: config,
	}
}

func NewGCPServiceAccountAuth(encryptedSA string) *TargetAuth {
	return &TargetAuth{
		Type:              AuthTypeGCPServiceAccount,
		GCPServiceAccount: &encryptedSA,
	}
}
