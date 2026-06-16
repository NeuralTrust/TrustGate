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

package response

import (
	"strings"
	"time"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
)

type GatewayResponse struct {
	ID              ids.GatewayID          `json:"id"`
	Name            string                 `json:"name"`
	Slug            string                 `json:"slug"`
	Status          string                 `json:"status"`
	Domain          string                 `json:"domain,omitempty"`
	Host            string                 `json:"host,omitempty"`
	Metadata        map[string]string      `json:"metadata,omitempty"`
	Telemetry       *telemetry.Telemetry   `json:"telemetry,omitempty"`
	ClientTLSConfig domain.ClientTLSConfig `json:"client_tls,omitempty"`
	SessionConfig   *domain.SessionConfig  `json:"session_config,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

func FromDomain(g *domain.Gateway, baseDomain string) GatewayResponse {
	if g == nil {
		return GatewayResponse{}
	}
	return GatewayResponse{
		ID:              g.ID,
		Name:            g.Name,
		Slug:            g.Slug,
		Status:          g.Status,
		Domain:          g.Domain,
		Host:            gatewayHost(g, baseDomain),
		Metadata:        g.Metadata,
		Telemetry:       g.Telemetry,
		ClientTLSConfig: g.ClientTLSConfig,
		SessionConfig:   g.SessionConfig,
		CreatedAt:       g.CreatedAt,
		UpdatedAt:       g.UpdatedAt,
	}
}

// gatewayHost returns the hostname clients use to reach the gateway: the custom
// domain when set, otherwise the {slug}.{baseDomain} subdomain.
func gatewayHost(g *domain.Gateway, baseDomain string) string {
	if g.Domain != "" {
		return g.Domain
	}
	baseDomain = strings.Trim(strings.TrimSpace(baseDomain), ".")
	if baseDomain == "" || g.Slug == "" {
		return ""
	}
	return g.Slug + "." + baseDomain
}
