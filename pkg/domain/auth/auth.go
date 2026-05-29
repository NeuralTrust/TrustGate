package auth

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Type string

const (
	TypeAPIKey Type = "api_key"
	TypeOAuth2 Type = "oauth2"
	TypeMTLS   Type = "mtls"
)

func Types() []Type {
	return []Type{TypeAPIKey, TypeOAuth2, TypeMTLS}
}

func IsValidType(t Type) bool {
	switch t {
	case TypeAPIKey, TypeOAuth2, TypeMTLS:
		return true
	}
	return false
}

type Auth struct {
	ID        uuid.UUID `json:"id"`
	GatewayID uuid.UUID `json:"gateway_id"`
	Name      string    `json:"name"`
	Type      Type      `json:"type"`
	Enabled   bool      `json:"enabled"`
	Config    Config    `json:"config"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func NewAuth(gatewayID uuid.UUID, name string, authType Type, enabled bool, config Config) (*Auth, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("auth: generate uuid: %w", err)
	}
	now := time.Now().UTC()
	a := &Auth{
		ID:        id,
		GatewayID: gatewayID,
		Name:      name,
		Type:      authType,
		Enabled:   enabled,
		Config:    config,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Auth) Validate() error {
	if strings.TrimSpace(a.Name) == "" {
		return ErrInvalidName
	}
	if a.GatewayID == uuid.Nil {
		return ErrInvalidGatewayID
	}
	if !IsValidType(a.Type) {
		return fmt.Errorf("%w: %q", ErrInvalidType, a.Type)
	}
	return a.Config.Validate(a.Type)
}
