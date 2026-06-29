// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gateway

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
)

const MetadataTeamIDKey = "team_id"

type Gateway struct {
	ID              ids.GatewayID        `json:"id"`
	Slug            string               `json:"slug"`
	Status          string               `json:"status"`
	Domain          string               `json:"domain,omitempty"`
	Metadata        map[string]string    `json:"metadata,omitempty"`
	Telemetry       *telemetry.Telemetry `json:"telemetry,omitempty"`
	ClientTLSConfig ClientTLSConfig      `json:"client_tls,omitempty"`
	SessionConfig   *SessionConfig       `json:"session_config,omitempty"`
	CreatedAt       time.Time            `json:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at"`
}

func (g *Gateway) TeamID() string {
	if g == nil || g.Metadata == nil {
		return ""
	}
	return g.Metadata[MetadataTeamIDKey]
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

func New(slug string) (*Gateway, error) {
	now := time.Now().UTC()
	g := &Gateway{
		ID:        ids.New[ids.GatewayKind](),
		Slug:      NormalizeSlug(slug),
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
	slug, status, domain string,
	tel *telemetry.Telemetry,
	clientTLS ClientTLSConfig,
	session *SessionConfig,
	createdAt, updatedAt time.Time,
) *Gateway {
	return &Gateway{
		ID:              id,
		Slug:            slug,
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
	g.Slug = NormalizeSlug(g.Slug)
	if g.Slug == "" {
		return fmt.Errorf("slug is required")
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

func IsValidSlug(slug string) bool {
	return slugPattern.MatchString(slug)
}
