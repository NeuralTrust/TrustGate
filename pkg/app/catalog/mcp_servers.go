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

package catalog

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/NeuralTrust/TrustGate/pkg/app/mcpoauth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	mcpcatalog "github.com/NeuralTrust/TrustGate/seed/mcp-catalog"
)

type MCPServerCatalog interface {
	ListMCPServers() []domain.MCPServer
	GetByCode(code string) (domain.MCPServer, bool)
	SharedOAuthCredentials(code string) (clientID, clientSecret string, ok bool)
}

var _ MCPServerCatalog = (*mcpServerCatalog)(nil)

type mcpServerCatalog struct {
	servers []domain.MCPServer
	byCode  map[string]domain.MCPServer
	shared  mcpoauth.Provider
}

func NewMCPServerCatalog(shared mcpoauth.Provider) (MCPServerCatalog, error) {
	servers, err := loadCuratedMCPServers()
	if err != nil {
		return nil, fmt.Errorf("loading curated mcp catalog: %w", err)
	}
	applyPlatformOAuth(servers, shared)
	// Whether a user can install each entry with nothing configured by an admin —
	// decided after the platform clients are stamped, since a platform-held
	// client makes a manual-registration OAuth server self-service.
	for i := range servers {
		servers[i].SelfService = servers[i].IsSelfService()
		// Same reason for deciding it here: a platform-held client leaves the
		// operator nothing to differ on, so it settles both questions.
		servers[i].MultiInstance = servers[i].SupportsInstances()
	}
	byCode := make(map[string]domain.MCPServer, len(servers))
	for _, s := range servers {
		byCode[s.Code] = s
	}
	return &mcpServerCatalog{servers: servers, byCode: byCode, shared: shared}, nil
}

func (c *mcpServerCatalog) ListMCPServers() []domain.MCPServer {
	out := make([]domain.MCPServer, len(c.servers))
	copy(out, c.servers)
	return out
}

func (c *mcpServerCatalog) GetByCode(code string) (domain.MCPServer, bool) {
	s, ok := c.byCode[code]
	return s, ok
}

func (c *mcpServerCatalog) SharedOAuthCredentials(code string) (string, string, bool) {
	if c.shared == nil {
		return "", "", false
	}
	creds, ok := c.shared.CredentialsFor(code)
	return creds.ClientID, creds.ClientSecret, ok
}

const curatedSource = "curated"

// authHintNone/Static/OAuth are the coarse auth classifications surfaced to the
// UI so it can prefill the right registry auth mode.
const (
	authHintNone   = "none"
	authHintStatic = "static"
	authHintOAuth  = "oauth"
)

// registrationAuto marks OAuth servers whose client self-registers (DCR), so no
// operator configuration is needed before connecting.
const registrationAuto = "auto"

// grantTypeClientCredentials marks machine-to-machine OAuth in the catalog.
const grantTypeClientCredentials = "client_credentials"

// rawCatalog mirrors the schema of seed/mcp-catalog/enterprise-servers.json.
type rawCatalog struct {
	Servers []rawServer `json:"servers"`
}

type rawServer struct {
	Name         string                  `json:"name"`
	Vendor       string                  `json:"vendor"`
	Category     string                  `json:"category"`
	Description  string                  `json:"description"`
	Transport    string                  `json:"transport"`
	ServerURL    string                  `json:"server_url"`
	URLVariables []domain.MCPURLVariable `json:"url_variables"`
	RequiresAuth bool                    `json:"requires_auth"`
	AuthHeaders  []domain.MCPAuthHeader  `json:"auth_headers"`
	OAuth        *domain.MCPOAuth        `json:"oauth"`
	// AuthMethods optionally overrides the derived list of installable auth
	// methods ("static" and/or "oauth"). Set it to offer a choice (e.g. both)
	// where the derivation alone would pick a single method.
	AuthMethods []string         `json:"auth_methods"`
	Tools       []domain.MCPTool `json:"tools"`
	Relevance   int              `json:"relevance"`
	// Hidden keeps the entry in the seed for audit/re-probe but omits it from
	// ListMCPServers (Admin UI / product catalog).
	Hidden       bool   `json:"hidden,omitempty"`
	HiddenReason string `json:"hidden_reason,omitempty"`
}

func loadCuratedMCPServers() ([]domain.MCPServer, error) {
	return parseCuratedMCPServers(mcpcatalog.EnterpriseServersJSON)
}

func parseCuratedMCPServers(data []byte) ([]domain.MCPServer, error) {
	var raw rawCatalog
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	servers := make([]domain.MCPServer, 0, len(raw.Servers))
	seen := make(map[string]struct{}, len(raw.Servers))
	for _, s := range raw.Servers {
		// The catalog code (seed "name") is the stable id the UI joins on to
		// detect already-connected servers, so it must be unique. Reject
		// duplicates at load time rather than serving an ambiguous catalog.
		if s.Name == "" {
			return nil, fmt.Errorf("mcp catalog: server has empty name")
		}
		if _, dup := seen[s.Name]; dup {
			return nil, fmt.Errorf("mcp catalog: duplicate server code %q", s.Name)
		}
		seen[s.Name] = struct{}{}
		if s.Hidden {
			continue
		}
		servers = append(servers, domain.MCPServer{
			Code:           s.Name,
			DisplayName:    s.Vendor,
			Vendor:         s.Vendor,
			Category:       s.Category,
			Description:    s.Description,
			URL:            s.ServerURL,
			Transport:      s.Transport,
			AuthHint:       authHint(s),
			AuthMethods:    authMethods(s),
			RequiresAuth:   s.RequiresAuth,
			RequiresConfig: requiresConfig(s),
			Relevance:      s.Relevance,
			URLVariables:   s.URLVariables,
			AuthHeaders:    s.AuthHeaders,
			OAuth:          s.OAuth,
			Tools:          s.Tools,
			Source:         curatedSource,
		})
	}
	// Most relevant first; ties broken alphabetically so the order is stable.
	sort.SliceStable(servers, func(i, j int) bool {
		if servers[i].Relevance != servers[j].Relevance {
			return servers[i].Relevance > servers[j].Relevance
		}
		if servers[i].DisplayName != servers[j].DisplayName {
			return servers[i].DisplayName < servers[j].DisplayName
		}
		return servers[i].Code < servers[j].Code
	})
	return servers, nil
}

// authHint classifies the upstream's auth model so the UI can prefill the
// registry auth mode.
func authHint(s rawServer) string {
	switch {
	case s.OAuth != nil && s.OAuth.Required:
		return authHintOAuth
	case len(s.AuthHeaders) > 0:
		return authHintStatic
	case s.RequiresAuth:
		return authHintStatic
	default:
		return authHintNone
	}
}

// authMethods lists every auth method an operator may pick when installing the
// server, each guaranteed renderable — the catalog never advertises a method the
// install UI has no field for. An explicit seed `auth_methods` wins (normalized/
// deduped); otherwise it is derived additively: "static" when the server has a
// slot for an operator-supplied credential (an auth header or a secret URL
// variable), "oauth" when it advertises an OAuth spec. A server that carries
// both therefore offers a choice. Empty derivation (public server) yields nil,
// and the UI treats a server with no declared methods as none.
func authMethods(s rawServer) []string {
	if len(s.AuthMethods) > 0 {
		return normalizeAuthMethods(s.AuthMethods)
	}
	var methods []string
	if hasStaticCredentialSlot(s) {
		methods = append(methods, authHintStatic)
	}
	if s.OAuth != nil {
		methods = append(methods, authHintOAuth)
	}
	return methods
}

// hasStaticCredentialSlot reports whether the server has somewhere for the
// operator to put a static credential: an auth header, or a secret URL variable
// (e.g. a `?token=` query value). Without a slot there is no field to enter an
// API key, so "static" is not offered even if the server otherwise requires auth.
func hasStaticCredentialSlot(s rawServer) bool {
	if len(s.AuthHeaders) > 0 {
		return true
	}
	for _, v := range s.URLVariables {
		if v.Secret {
			return true
		}
	}
	return false
}

// normalizeAuthMethods keeps only recognized method identifiers, in a stable
// order (static before oauth), dropping duplicates and "none".
func normalizeAuthMethods(raw []string) []string {
	seen := make(map[string]struct{}, len(raw))
	for _, m := range raw {
		seen[m] = struct{}{}
	}
	var out []string
	for _, m := range []string{authHintStatic, authHintOAuth} {
		if _, ok := seen[m]; ok {
			out = append(out, m)
		}
	}
	return out
}

// requiresConfig reports whether the operator must supply input before the
// server can be connected, so the UI can connect zero-config servers by default
// and only surface a setup step for the rest.
func requiresConfig(s rawServer) bool {
	for _, v := range s.URLVariables {
		if v.Required {
			return true
		}
	}
	switch authHint(s) {
	case authHintNone:
		return false
	case authHintStatic:
		return true
	case authHintOAuth:
		if s.OAuth != nil && s.OAuth.GrantType == grantTypeClientCredentials {
			return true
		}
		return s.OAuth.Registration != registrationAuto
	default:
		return true
	}
}

func applyPlatformOAuth(servers []domain.MCPServer, shared mcpoauth.Provider) {
	if shared == nil {
		return
	}
	for i := range servers {
		if _, ok := shared.CredentialsFor(servers[i].Code); !ok {
			continue
		}
		servers[i].PlatformClient = true
		if !needsNonOAuthConfig(servers[i]) {
			servers[i].RequiresConfig = false
		}
	}
}

func needsNonOAuthConfig(s domain.MCPServer) bool {
	for _, v := range s.URLVariables {
		if v.Required {
			return true
		}
	}
	if s.AuthHint == authHintStatic {
		return true
	}
	return s.OAuth != nil && s.OAuth.GrantType == grantTypeClientCredentials
}
