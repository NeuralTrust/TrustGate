package gateway

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
	"github.com/google/uuid"
)

type Gateway struct {
	ID              ids.GatewayID        `json:"id"`
	Name            string               `json:"name"`
	Slug            string               `json:"slug"`
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

var slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func New(name string, slug ...string) (*Gateway, error) {
	now := time.Now().UTC()
	g := &Gateway{
		ID:        ids.New[ids.GatewayKind](),
		Name:      name,
		Slug:      firstSlug(name, slug),
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
		Slug:            SlugFromName(name),
		Status:          status,
		Domain:          domain,
		Telemetry:       tel,
		ClientTLSConfig: clientTLS,
		SessionConfig:   session,
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
	}
}

func RehydrateWithSlug(
	id ids.GatewayID,
	name, slug, status string,
	tel *telemetry.Telemetry,
	clientTLS ClientTLSConfig,
	session *SessionConfig,
	createdAt, updatedAt time.Time,
) *Gateway {
	g := Rehydrate(id, name, status, "", tel, clientTLS, session, createdAt, updatedAt)
	g.Slug = slug
	return g
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

	if g.Slug == "" {
		g.Slug = SlugFromName(g.Name)
	} else {
		g.Slug = NormalizeSlug(g.Slug)
	}
	if !IsValidSlug(g.Slug) {
		return fmt.Errorf("slug must be a lowercase DNS label")
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
	if strings.Contains(d, "*") {
		return "", fmt.Errorf("%w: %q wildcard domains are not supported", ErrInvalidDomain, domain)
	}
	if strings.HasSuffix(d, ".") || strings.HasPrefix(d, ".") {
		return "", fmt.Errorf("%w: %q must not start or end with a dot", ErrInvalidDomain, domain)
	}
	for _, r := range d {
		valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.'
		if !valid {
			return "", fmt.Errorf("%w: %q contains invalid hostname characters", ErrInvalidDomain, domain)
		}
	}
	return d, nil
}

func NormalizeSlug(slug string) string {
	return strings.ToLower(strings.TrimSpace(slug))
}

func SlugFromName(name string) string {
	name = NormalizeSlug(name)
	var b strings.Builder
	lastDash := false
	for _, r := range name {
		valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if valid {
			if b.Len() < 63 {
				b.WriteRune(r)
			}
			lastDash = false
			continue
		}
		if b.Len() == 0 || lastDash || b.Len() >= 63 {
			continue
		}
		b.WriteByte('-')
		lastDash = true
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "gateway-" + uuid.NewString()[:8]
	}
	return out
}

func IsValidSlug(slug string) bool {
	return slugPattern.MatchString(slug)
}

func firstSlug(name string, slug []string) string {
	if len(slug) == 0 {
		return SlugFromName(name)
	}
	return NormalizeSlug(slug[0])
}
