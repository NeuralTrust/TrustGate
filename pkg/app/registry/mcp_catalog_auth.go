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

package registry

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

const grantTypeClientCredentials = "client_credentials"

// MCPAuthCatalog looks up curated MCP server metadata used to canonicalize
// client_credentials auth. Defined here (instead of importing app/catalog) to
// avoid an import cycle with catalog → registry.
type MCPAuthCatalog interface {
	GetByCode(code string) (catalogdomain.MCPServer, bool)
}

// CanonicalizeMCPAuthFromCatalog overwrites client-supplied token endpoint
// metadata from the curated catalog when the registry was created from a
// catalog code. This prevents an operator from redirecting a client secret to
// an attacker-controlled token URL.
func CanonicalizeMCPAuthFromCatalog(target *domain.MCPTarget, catalog MCPAuthCatalog) error {
	if target == nil {
		return nil
	}
	code := strings.TrimSpace(target.Code)
	if code == "" {
		return nil
	}
	// Fail closed: without the catalog a client-supplied token_url could not be
	// checked against the curated entry it claims to be.
	if catalog == nil {
		return fmt.Errorf("%w: mcp catalog unavailable; cannot verify catalog entry %q",
			commonerrors.ErrValidation, code)
	}
	entry, ok := catalog.GetByCode(code)
	if !ok || entry.OAuth == nil || !entry.OAuth.Required {
		return nil
	}
	if entry.OAuth.GrantType != grantTypeClientCredentials {
		return nil
	}
	if target.Auth == nil {
		target.Auth = &domain.MCPAuth{}
	}
	if mode := strings.TrimSpace(string(target.Auth.Mode)); mode != "" && mode != string(domain.MCPAuthModeClientCredentials) {
		return fmt.Errorf("%w: catalog entry %q requires auth mode client_credentials", commonerrors.ErrValidation, code)
	}
	if strings.TrimSpace(entry.OAuth.TokenURL) == "" {
		return fmt.Errorf("%w: catalog entry %q is missing oauth.token_url", commonerrors.ErrValidation, code)
	}
	target.Auth.Mode = domain.MCPAuthModeClientCredentials
	target.Auth.TokenURL = entry.OAuth.TokenURL
	target.Auth.Scopes = append([]string(nil), entry.OAuth.Scopes...)
	target.Auth.TokenEndpointAuthMethod = entry.OAuth.TokenEndpointAuthMethod
	if target.Auth.TokenEndpointAuthMethod == "" {
		target.Auth.TokenEndpointAuthMethod = domain.TokenEndpointAuthClientSecretBasic
	}
	switch resource := strings.TrimSpace(entry.OAuth.Resource); {
	case resource != "":
		target.Auth.Resource = resource
	case entry.OAuth.ResourceMetadata:
		target.Auth.Resource = target.URL
	default:
		// The audience is part of what the catalog vouches for; never keep a
		// client-supplied resource indicator.
		target.Auth.Resource = ""
	}
	// Drop authorization-code fields that do not apply to M2M.
	target.Auth.Provider = ""
	target.Auth.Registration = ""
	target.Auth.AuthorizeURL = ""
	target.Auth.Header = ""
	target.Auth.Value = ""
	return nil
}
