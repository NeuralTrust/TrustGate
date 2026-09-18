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

type MCPAuthCatalog interface {
	GetByCode(code string) (catalogdomain.MCPServer, bool)
	SharedOAuthCredentials(code string) (clientID, clientSecret string, ok bool)
}

func CanonicalizeMCPAuthFromCatalog(target *domain.MCPTarget, catalog MCPAuthCatalog) error {
	if target == nil {
		return nil
	}
	code := strings.TrimSpace(target.Code)
	if code == "" {
		return nil
	}
	if catalog == nil {
		return fmt.Errorf("%w: mcp catalog unavailable; cannot verify catalog entry %q",
			commonerrors.ErrValidation, code)
	}
	entry, ok := catalog.GetByCode(code)
	if !ok || entry.OAuth == nil || !entry.OAuth.Required {
		return nil
	}
	// An entry may advertise more than one install method: GitHub's hosted MCP
	// takes an OAuth login or a PAT in Authorization: Bearer, and the catalog
	// declares both (auth_methods). OAuth being required is what the OAuth path
	// must obey, not a claim that it is the only path.
	if target.Auth != nil && target.Auth.Mode == domain.MCPAuthModeStatic {
		if static, _ := entry.SupportedAuthMethods(); static {
			return canonicalizeStatic(target, entry, code)
		}
	}
	if entry.OAuth.GrantType == grantTypeClientCredentials {
		return canonicalizeClientCredentials(target, entry, code)
	}
	if err := canonicalizeAuthorizationCode(target, entry, code); err != nil {
		return err
	}
	injectSharedOAuth(target, catalog)
	return nil
}

// canonicalizeStatic keeps the operator's own credential, naming the header from
// the entry when the caller left it out. Every OAuth-shaped field is dropped:
// switching an installed instance from forwarded to static echoes back the OAuth
// block the read API emitted, and a record carrying both shapes misreports how
// the target dials — a masked client secret among them would then fail the
// forwarded validation if the instance were ever switched back.
func canonicalizeStatic(target *domain.MCPTarget, entry catalogdomain.MCPServer, code string) error {
	if len(entry.AuthHeaders) == 0 {
		return fmt.Errorf("%w: catalog entry %q offers auth mode static but declares no auth header to carry the credential",
			commonerrors.ErrValidation, code)
	}
	if strings.TrimSpace(target.Auth.Header) == "" {
		target.Auth.Header = strings.TrimSpace(entry.AuthHeaders[0].Name)
	}
	target.Auth.Provider = ""
	target.Auth.Registration = ""
	target.Auth.ClientID = ""
	target.Auth.ClientSecret = ""
	target.Auth.AuthorizeURL = ""
	target.Auth.TokenURL = ""
	target.Auth.Scopes = nil
	target.Auth.Resource = ""
	target.Auth.TokenEndpointAuthMethod = ""
	return nil
}

// acceptedAuthModes names the modes an install may declare for the entry, in the
// order the install UI offers them. Called only past the OAuth.Required gate, so
// entry.OAuth is non-nil.
func acceptedAuthModes(entry catalogdomain.MCPServer) []string {
	var modes []string
	if static, _ := entry.SupportedAuthMethods(); static && len(entry.AuthHeaders) > 0 {
		modes = append(modes, string(domain.MCPAuthModeStatic))
	}
	if entry.OAuth.GrantType == grantTypeClientCredentials {
		return append(modes, string(domain.MCPAuthModeClientCredentials))
	}
	return append(modes, string(domain.MCPAuthModeForwarded))
}

func errUnsupportedAuthMode(code, mode string, entry catalogdomain.MCPServer) error {
	return fmt.Errorf("%w: catalog entry %q accepts auth mode %s, got %q",
		commonerrors.ErrValidation, code, strings.Join(acceptedAuthModes(entry), " or "), mode)
}

func canonicalizeClientCredentials(target *domain.MCPTarget, entry catalogdomain.MCPServer, code string) error {
	if target.Auth == nil {
		target.Auth = &domain.MCPAuth{}
	}
	if mode := strings.TrimSpace(string(target.Auth.Mode)); mode != "" && mode != string(domain.MCPAuthModeClientCredentials) {
		return errUnsupportedAuthMode(code, mode, entry)
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
		target.Auth.Resource = ""
	}
	target.Auth.Provider = ""
	target.Auth.Registration = ""
	target.Auth.AuthorizeURL = ""
	target.Auth.Header = ""
	target.Auth.Value = ""
	return nil
}

func canonicalizeAuthorizationCode(target *domain.MCPTarget, entry catalogdomain.MCPServer, code string) error {
	if target.Auth == nil {
		target.Auth = &domain.MCPAuth{}
	}
	if mode := strings.TrimSpace(string(target.Auth.Mode)); mode != "" && mode != string(domain.MCPAuthModeForwarded) {
		return errUnsupportedAuthMode(code, mode, entry)
	}
	target.Auth.Mode = domain.MCPAuthModeForwarded
	if strings.TrimSpace(target.Auth.Provider) == "" {
		target.Auth.Provider = code
	}
	if reg := strings.TrimSpace(entry.OAuth.Registration); reg != "" {
		target.Auth.Registration = domain.MCPClientRegistration(reg)
	}
	if target.Auth.Registration == "" {
		target.Auth.Registration = domain.RegistrationManual
	}
	if target.Auth.Registration != domain.RegistrationAuto {
		hasAuthorizeURL := strings.TrimSpace(entry.OAuth.AuthorizeURL) != ""
		hasTokenURL := strings.TrimSpace(entry.OAuth.TokenURL) != ""
		if hasAuthorizeURL != hasTokenURL {
			return fmt.Errorf("%w: catalog entry %q is missing oauth.authorize_url/token_url", commonerrors.ErrValidation, code)
		}
		if !hasAuthorizeURL && !entry.OAuth.ResourceMetadata {
			return fmt.Errorf("%w: catalog entry %q cannot discover oauth.authorize_url/token_url", commonerrors.ErrValidation, code)
		}
		if hasAuthorizeURL {
			target.Auth.AuthorizeURL = entry.OAuth.AuthorizeURL
			target.Auth.TokenURL = entry.OAuth.TokenURL
		}
	} else {
		if entry.OAuth.AuthorizeURL != "" {
			target.Auth.AuthorizeURL = entry.OAuth.AuthorizeURL
		}
		if entry.OAuth.TokenURL != "" {
			target.Auth.TokenURL = entry.OAuth.TokenURL
		}
	}
	if len(entry.OAuth.Scopes) > 0 {
		target.Auth.Scopes = append([]string(nil), entry.OAuth.Scopes...)
	}
	switch resource := strings.TrimSpace(entry.OAuth.Resource); {
	case resource != "":
		target.Auth.Resource = resource
	case entry.OAuth.ResourceMetadata && strings.TrimSpace(target.Auth.Resource) == "":
		target.Auth.Resource = target.URL
	}
	return nil
}

func injectSharedOAuth(target *domain.MCPTarget, catalog MCPAuthCatalog) {
	if target == nil || target.Auth == nil || catalog == nil {
		return
	}
	if target.Auth.Mode != domain.MCPAuthModeForwarded {
		return
	}
	if target.Auth.Registration == domain.RegistrationAuto {
		return
	}
	clientID, clientSecret, ok := catalog.SharedOAuthCredentials(target.Code)
	if !ok {
		return
	}
	if id := strings.TrimSpace(target.Auth.ClientID); id != "" && id != clientID {
		return
	}
	target.Auth.ClientID = clientID
	target.Auth.ClientSecret = clientSecret
}
