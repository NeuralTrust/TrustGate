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

package store

import (
	"strings"
	"time"

	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// catalogRegistry materialises the shared registry for a catalog entry — the
// "created on first install" shape from the design memo. It carries only what
// is shared across users: the upstream URL (a template for servers with URL
// variables), transport, and the auth mode. Per-user values (URL variable
// values) live on the installation; per-user credentials live in the vault.
//
// The result is always available on the shelf (self-service). It is the same
// shape an admin would get by connecting the catalog server from the registry
// side panel, so a self-serviced server and an admin-shelved one are identical.
func catalogRegistry(entry catalogdomain.MCPServer, gatewayID ids.GatewayID) (*registrydomain.Registry, error) {
	id, err := ids.NewV7[ids.RegistryKind]()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	return &registrydomain.Registry{
		ID:        id,
		GatewayID: gatewayID,
		Name:      displayName(entry, entry.Code),
		Type:      registrydomain.TypeMCP,
		Enabled:   true,
		MCPTarget: catalogMCPTarget(entry),
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// catalogMCPTarget builds the shared mcp_target for a catalog entry: URL (or its
// template), transport, auth mode, and an available Store shelf. Secrets and
// per-user URL variable values are never in the catalog, so they stay empty.
func catalogMCPTarget(entry catalogdomain.MCPServer) *registrydomain.MCPTarget {
	transport := registrydomain.MCPTransport(strings.TrimSpace(entry.Transport))
	if transport == "" {
		transport = registrydomain.MCPTransportStreamableHTTP
	}
	target := &registrydomain.MCPTarget{
		Code:         entry.Code,
		Source:       registrydomain.MCPSourceRemote,
		URL:          entry.URL,
		Transport:    transport,
		Auth:         catalogAuth(entry),
		Store:        &registrydomain.MCPStoreConfig{Available: true},
		URLVariables: catalogURLVariables(entry.URLVariables),
	}
	target.Normalize()
	return target
}

// catalogURLVariables copies the catalog entry's per-user URL placeholder
// declarations onto the registry, so the dial path knows which values to
// substitute (and which are secret) without re-reading the catalog. The value of
// each variable is never in the catalog — it is supplied per principal at
// install time — so only the declaration is carried.
func catalogURLVariables(vars []catalogdomain.MCPURLVariable) []registrydomain.MCPURLVariable {
	if len(vars) == 0 {
		return nil
	}
	out := make([]registrydomain.MCPURLVariable, 0, len(vars))
	for _, v := range vars {
		out = append(out, registrydomain.MCPURLVariable{
			Name:        strings.TrimSpace(v.Name),
			Description: v.Description,
			Required:    v.Required,
			Secret:      v.Secret,
			In:          strings.TrimSpace(v.In),
		})
	}
	return out
}

// catalogAuth maps a catalog entry's auth hint onto the registry's upstream auth
// mode. It sets only the shared shape — secrets (static value, client secret)
// and per-user tokens are never in the catalog, so they stay empty and are
// supplied at connect time (vault) or by the admin editing the shelf.
func catalogAuth(entry catalogdomain.MCPServer) *registrydomain.MCPAuth {
	switch strings.ToLower(strings.TrimSpace(entry.AuthHint)) {
	case "", "none":
		return &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeNone}
	case "static":
		auth := &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeStatic}
		// The header name is catalog metadata; its value is a per-user secret
		// provided at connect time, so it is left blank here.
		if len(entry.AuthHeaders) > 0 {
			auth.Header = strings.TrimSpace(entry.AuthHeaders[0].Name)
		}
		return auth
	case "oauth":
		return catalogOAuth(entry.OAuth)
	default:
		return &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeNone}
	}
}

func catalogOAuth(o *catalogdomain.MCPOAuth) *registrydomain.MCPAuth {
	if o == nil {
		return &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeForwarded, Registration: registrydomain.RegistrationAuto}
	}
	if strings.EqualFold(strings.TrimSpace(o.GrantType), "client_credentials") {
		// Machine-to-machine: client id/secret are admin-provided, not in the
		// catalog, so they are left blank for the admin to fill on the shelf.
		return &registrydomain.MCPAuth{
			Mode:     registrydomain.MCPAuthModeClientCredentials,
			TokenURL: strings.TrimSpace(o.TokenURL),
			Scopes:   o.Scopes,
			Resource: strings.TrimSpace(o.Resource),
		}
	}
	auth := &registrydomain.MCPAuth{
		Mode:         registrydomain.MCPAuthModeForwarded,
		AuthorizeURL: strings.TrimSpace(o.AuthorizeURL),
		TokenURL:     strings.TrimSpace(o.TokenURL),
		Scopes:       o.Scopes,
		Resource:     strings.TrimSpace(o.Resource),
	}
	if strings.EqualFold(strings.TrimSpace(o.Registration), "manual") {
		auth.Registration = registrydomain.RegistrationManual
	} else {
		auth.Registration = registrydomain.RegistrationAuto
	}
	return auth
}
