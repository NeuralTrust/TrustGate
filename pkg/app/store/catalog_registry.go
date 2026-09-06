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

// catalogAuth maps a catalog entry's auth declaration onto the registry's
// upstream auth mode. It sets only the shared shape — secrets (static value,
// client secret) and per-user tokens are never in the catalog, so they stay
// empty and are supplied at connect time (vault) or by the admin editing the
// shelf.
//
// A server that offers OAuth (alone or alongside an API key) is materialised
// with forwarded auth: that is the one method a self-service user can complete
// on their own (they log in), so it is what the shared registry carries. A
// static-only server with a header credential is mapped to static with the
// header name and no value — such a registry cannot validate, which is exactly
// why the installer refuses to self-serve it (catalogNeedsAdminCredential). A
// static-only server whose credential is a secret URL variable needs no upstream
// header at all: the per-user value is substituted into the URL from the vault,
// so it maps to none.
func catalogAuth(entry catalogdomain.MCPServer) *registrydomain.MCPAuth {
	static, oauth := catalogAuthMethods(entry)
	switch {
	case oauth:
		return catalogOAuth(entry.Code, entry.OAuth)
	case static && len(entry.AuthHeaders) > 0:
		return &registrydomain.MCPAuth{
			Mode:   registrydomain.MCPAuthModeStatic,
			Header: strings.TrimSpace(entry.AuthHeaders[0].Name),
		}
	default:
		return &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeNone}
	}
}

// catalogAuthMethods reports which auth methods a catalog entry offers. The
// explicit AuthMethods list is authoritative when present; otherwise the methods
// are derived from the coarse hint and the entry's shape (an OAuth spec ⇒ oauth,
// a static hint or an auth header ⇒ static).
func catalogAuthMethods(entry catalogdomain.MCPServer) (static, oauth bool) {
	if len(entry.AuthMethods) > 0 {
		for _, m := range entry.AuthMethods {
			switch strings.ToLower(strings.TrimSpace(m)) {
			case "static":
				static = true
			case "oauth":
				oauth = true
			}
		}
		return static, oauth
	}
	hint := strings.ToLower(strings.TrimSpace(entry.AuthHint))
	oauth = hint == "oauth" || entry.OAuth != nil
	static = hint == "static" || len(entry.AuthHeaders) > 0
	return static, oauth
}

// catalogNeedsAdminCredential reports whether a catalog entry cannot be
// self-served because it needs a credential only an admin can add on the shelf:
//
//   - a static-only server whose credential is a shared header value (an API
//     key) the catalog does not carry; or
//   - an OAuth server whose client cannot be obtained by the gateway itself: a
//     client_credentials grant (admin-provided client), or a manual registration
//     with no platform-held client.
//
// Self-serviceable, by contrast: OAuth with dynamic client registration (auto)
// or a platform-held client (the user just logs in), and a static-only server
// whose credential is a secret URL variable (each user enters their own value
// through the hosted form).
func catalogNeedsAdminCredential(entry catalogdomain.MCPServer) bool {
	static, oauth := catalogAuthMethods(entry)
	if oauth {
		return !oauthSelfServiceable(entry)
	}
	if !static {
		return false
	}
	if len(entry.AuthHeaders) == 0 && hasSecretURLVariable(entry) {
		return false
	}
	return true
}

// oauthSelfServiceable reports whether the gateway can complete this entry's
// OAuth flow without an admin: the client is registered dynamically (auto) or
// held by the platform. A required OAuth with no declared registration is
// canonicalised to manual by the registry creator, so it needs an admin unless
// a platform client exists; an optional OAuth with no declared registration
// keeps the auto mapping.
func oauthSelfServiceable(entry catalogdomain.MCPServer) bool {
	o := entry.OAuth
	if o == nil {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(o.GrantType), "client_credentials") {
		return false
	}
	if entry.PlatformClient {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(o.Registration)) {
	case "auto":
		return true
	case "":
		return !o.Required
	default:
		return false
	}
}

func hasSecretURLVariable(entry catalogdomain.MCPServer) bool {
	for _, v := range entry.URLVariables {
		if v.Secret {
			return true
		}
	}
	return false
}

// catalogOAuth maps a catalog OAuth spec onto the registry's auth. Forwarded auth
// carries the catalog code as its provider — the per-user token's vault key — so
// the materialised target validates and dials exactly like an admin-shelved one.
func catalogOAuth(code string, o *catalogdomain.MCPOAuth) *registrydomain.MCPAuth {
	if o == nil {
		return &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     strings.TrimSpace(code),
			Registration: registrydomain.RegistrationAuto,
		}
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
		Provider:     strings.TrimSpace(code),
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
