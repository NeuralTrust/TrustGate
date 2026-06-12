package gateway

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
)

type Gateway struct {
	ID              ids.GatewayID        `json:"id"`
	Name            string               `json:"name"`
	Status          string               `json:"status"`
	Domain          string               `json:"domain,omitempty"`
	Telemetry       *telemetry.Telemetry `json:"telemetry,omitempty"`
	ClientTLSConfig ClientTLSConfig      `json:"client_tls,omitempty"`
	SessionConfig   *SessionConfig       `json:"session_config,omitempty"`
	CreatedAt       time.Time            `json:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at"`
}

type SessionConfig struct {
	Enabled       *bool  `json:"enabled,omitempty"`
	HeaderName    string `json:"header_name,omitempty"`
	BodyParamName string `json:"body_param_name,omitempty"`
}

func (s *SessionConfig) IsEnabled() bool {
	if s == nil {
		return true
	}
	if s.Enabled == nil {
		return true
	}
	return *s.Enabled
}

func DefaultSessionConfig() *SessionConfig {
	enabled := true
	return &SessionConfig{Enabled: &enabled}
}

func New(name string) (*Gateway, error) {
	now := time.Now().UTC()
	g := &Gateway{
		ID:        ids.New[ids.GatewayKind](),
		Name:      name,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := g.Validate(); err != nil {
		return nil, err
	}
	return g, nil
}

func Rehydrate(
	id ids.GatewayID,
	name, status, domain string,
	tel *telemetry.Telemetry,
	clientTLS ClientTLSConfig,
	session *SessionConfig,
	createdAt, updatedAt time.Time,
) *Gateway {
	return &Gateway{
		ID:              id,
		Name:            name,
		Status:          status,
		Domain:          domain,
		Telemetry:       tel,
		ClientTLSConfig: clientTLS,
		SessionConfig:   session,
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
	}
}

type ClientTLSConfig map[string]json.RawMessage

func (c ClientTLSConfig) Value() (driver.Value, error) {
	if c == nil {
		return nil, nil
	}
	return json.Marshal(c)
}

func (c *ClientTLSConfig) Scan(value interface{}) error {
	if value == nil {
		*c = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, c)
}

func (g *Gateway) Validate() error {
	if g.Name == "" {
		return fmt.Errorf("name is required")
	}

	if g.Status == "" {
		g.Status = "active"
	}

	domain, err := NormalizeDomain(g.Domain)
	if err != nil {
		return err
	}
	g.Domain = domain

	return nil
}

func NormalizeDomain(domain string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return "", nil
	}
	if strings.ContainsAny(d, "/:?# ") {
		return "", fmt.Errorf("%w: %q must be a bare hostname (no scheme, port or path)", ErrInvalidDomain, domain)
	}
	return d, nil
}
