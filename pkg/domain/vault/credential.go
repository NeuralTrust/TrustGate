package vault

import (
	"context"
	"fmt"
	"strings"
	"time"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

var (
	ErrInvalidCredential = fmt.Errorf("vault: invalid credential: %w", commonerrors.ErrValidation)
	ErrNotFound          = fmt.Errorf("vault: credential not found: %w", commonerrors.ErrNotFound)
)

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
	id, err := ids.NewV7[ids.VaultKind]()
	if err != nil {
		return nil, fmt.Errorf("vault: generate uuid: %w", err)
	}
	now := time.Now().UTC()
	return &Credential{
		ID:           id,
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

func (c *Credential) Expired(skew time.Duration) bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().Add(skew).After(c.ExpiresAt)
}

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=vault_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Upsert(ctx context.Context, c *Credential) error
	Find(ctx context.Context, gatewayID ids.GatewayID, principalSub, provider string) (*Credential, error)
	ListByPrincipal(ctx context.Context, gatewayID ids.GatewayID, principalSub string) ([]*Credential, error)
	Delete(ctx context.Context, gatewayID ids.GatewayID, principalSub, provider string) error
}
