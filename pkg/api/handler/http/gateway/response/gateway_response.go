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
	"github.com/NeuralTrust/AgentGateway/pkg/version"
)

type GatewayResponse struct {
	ID              ids.GatewayID          `json:"id"`
	Name            string                 `json:"name"`
	Slug            string                 `json:"slug"`
	Status          string                 `json:"status"`
	Version         string                 `json:"version"`
	Domain          string                 `json:"domain,omitempty"`
	Hosts           GatewayHosts           `json:"hosts"`
	Metadata        map[string]string      `json:"metadata,omitempty"`
	Telemetry       *telemetry.Telemetry   `json:"telemetry,omitempty"`
	ClientTLSConfig domain.ClientTLSConfig `json:"client_tls,omitempty"`
	SessionConfig   *domain.SessionConfig  `json:"session_config,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// GatewayHosts holds the hostnames clients use to reach the gateway on each
// plane: Proxy for the LLM proxy and MCP for the Model Context Protocol server.
type GatewayHosts struct {
	Proxy string `json:"proxy,omitempty"`
	MCP   string `json:"mcp,omitempty"`
}

func FromDomain(g *domain.Gateway, proxyBaseDomain, mcpBaseDomain string) GatewayResponse {
	if g == nil {
		return GatewayResponse{}
	}
	return GatewayResponse{
		ID:      g.ID,
		Name:    g.Name,
		Slug:    g.Slug,
		Status:  g.Status,
		Version: version.Version,
		Domain:  g.Domain,
		Hosts: GatewayHosts{
			Proxy: proxyHost(g, proxyBaseDomain),
			MCP:   subdomainHost(g.Slug, mcpBaseDomain),
		},
		Metadata:        g.Metadata,
		Telemetry:       g.Telemetry,
		ClientTLSConfig: g.ClientTLSConfig,
		SessionConfig:   g.SessionConfig,
		CreatedAt:       g.CreatedAt,
		UpdatedAt:       g.UpdatedAt,
	}
}

func proxyHost(g *domain.Gateway, baseDomain string) string {
	if g.Domain != "" {
		return g.Domain
	}
	return subdomainHost(g.Slug, baseDomain)
}

func subdomainHost(slug, baseDomain string) string {
	baseDomain = strings.Trim(strings.TrimSpace(baseDomain), ".")
	if baseDomain == "" || slug == "" {
		return ""
	}
	return slug + "." + baseDomain
}
