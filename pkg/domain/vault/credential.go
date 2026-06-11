// Package vault holds durable, encrypted third-party credentials obtained
// through one-time user consent (the "forwarded" downstream auth mode).
// Unlike exchange tokens, these cannot be re-derived from the inbound token:
// losing a refresh token forces the user back through consent.
package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

var (
	ErrInvalidCredential = errors.New("vault: invalid credential")
	ErrNotFound          = errors.New("vault: credential not found")
)

// Credential is one linked third-party account, strictly isolated per
// (gateway, principal, provider). AccessToken/RefreshToken are stored
// encrypted at rest; a leak here is cross-user account takeover.
type Credential struct {
	ID           ids.VaultID
	GatewayID    ids.GatewayID
	PrincipalSub string
	Provider     string
	AccountRef   string
	AccessToken  string
	RefreshToken string
	Scopes       []string
	ExpiresAt    time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func NewCredential(
	gatewayID ids.GatewayID,
	principalSub, provider, accountRef, accessToken, refreshToken string,
	scopes []string,
	expiresAt time.Time,
) (*Credential, error) {
	if gatewayID.IsNil() {
		return nil, fmt.Errorf("%w: gateway id is required", ErrInvalidCredential)
	}
	if strings.TrimSpace(principalSub) == "" {
		return nil, fmt.Errorf("%w: principal subject is required", ErrInvalidCredential)
	}
	if strings.TrimSpace(provider) == "" {
		return nil, fmt.Errorf("%w: provider is required", ErrInvalidCredential)
	}
	if accessToken == "" {
		return nil, fmt.Errorf("%w: access token is required", ErrInvalidCredential)
	}
	now := time.Now().UTC()
	return &Credential{
		ID:           ids.New[ids.VaultKind](),
		GatewayID:    gatewayID,
		PrincipalSub: principalSub,
		Provider:     provider,
		AccountRef:   accountRef,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Scopes:       scopes,
		ExpiresAt:    expiresAt,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

// Expired reports whether the access token is past (or within skew of) expiry.
func (c *Credential) Expired(skew time.Duration) bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().Add(skew).After(c.ExpiresAt)
}

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=vault_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	// Upsert stores or replaces the credential for (gateway, principal, provider).
	Upsert(ctx context.Context, c *Credential) error
	// Find returns the credential for (gateway, principal, provider), or ErrNotFound.
	Find(ctx context.Context, gatewayID ids.GatewayID, principalSub, provider string) (*Credential, error)
	// ListByPrincipal returns all linked accounts of a principal in a gateway.
	ListByPrincipal(ctx context.Context, gatewayID ids.GatewayID, principalSub string) ([]*Credential, error)
	// Delete revokes a linked account.
	Delete(ctx context.Context, gatewayID ids.GatewayID, principalSub, provider string) error
}
