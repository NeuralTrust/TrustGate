package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

const apiKeyPrefix = "ag_"

const apiKeyEntropyBytes = 32

type Type string

const (
	TypeAPIKey       Type = "api_key"
	TypeOAuth2       Type = "oauth2"
	TypeOAuth2Client Type = "oauth2_client"
	TypeIDP          Type = "idp"
	TypeMTLS         Type = "mtls"
)

func Types() []Type {
	return []Type{TypeAPIKey, TypeOAuth2, TypeOAuth2Client, TypeIDP, TypeMTLS}
}

func IsValidType(t Type) bool {
	switch t {
	case TypeAPIKey, TypeOAuth2, TypeOAuth2Client, TypeIDP, TypeMTLS:
		return true
	}
	return false
}

func ConflictingAttachmentTypes(t Type) []Type {
	switch t {
	case TypeOAuth2Client:
		return []Type{TypeOAuth2Client, TypeOAuth2}
	case TypeOAuth2:
		return []Type{TypeOAuth2Client}
	}
	return nil
}

type Auth struct {
	ID        ids.AuthID    `json:"id"`
	GatewayID ids.GatewayID `json:"gateway_id"`
	Name      string        `json:"name"`
	Type      Type          `json:"type"`
	Enabled   bool          `json:"enabled"`
	Config    Config        `json:"config"`
	KeyHash   string        `json:"-"`
	RawKey    string        `json:"-"`
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

func NewAPIKeyAuth(gatewayID ids.GatewayID, name string, enabled bool) (*Auth, error) {
	rawKey, err := GenerateAPIKey()
	if err != nil {
		return nil, fmt.Errorf("auth: generate api key: %w", err)
	}
	a, err := NewAuth(gatewayID, name, TypeAPIKey, enabled, Config{})
	if err != nil {
		return nil, err
	}
	a.RawKey = rawKey
	a.KeyHash = HashAPIKey(rawKey)
	return a, nil
}

func GenerateAPIKey() (string, error) {
	buf := make([]byte, apiKeyEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return apiKeyPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

func HashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
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
