package auth

import (
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
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
	ID        ids.AuthID    `json:"id"`
	GatewayID ids.GatewayID `json:"gateway_id"`
	Name      string        `json:"name"`
	Type      Type          `json:"type"`
	Enabled   bool          `json:"enabled"`
	Config    Config        `json:"config"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
}

func NewAuth(gatewayID ids.GatewayID, name string, authType Type, enabled bool, config Config) (*Auth, error) {
	id, err := ids.NewV7[ids.AuthKind]()
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
	if a.GatewayID.IsNil() {
		return ErrInvalidGatewayID
	}
	if !IsValidType(a.Type) {
		return fmt.Errorf("%w: %q", ErrInvalidType, a.Type)
	}
	return a.Config.Validate(a.Type)
}
