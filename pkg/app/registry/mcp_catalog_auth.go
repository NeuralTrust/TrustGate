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

	"github.com/NeuralTrust/TrustGate/pkg/app/mcpoauth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

const grantTypeClientCredentials = "client_credentials"

type MCPAuthCatalog interface {
	GetByCode(code string) (catalogdomain.MCPServer, bool)
	SharedOAuthCredentials(code string) (clientID, clientSecret string, ok bool)
}

// RequireAdminBoundURLVariables rejects a registry save while a required
// non-secret URL placeholder is still open, or while a value the admin wrote
// fails the catalog rules: ValidateURLValues (charset and closed options),
// the variable's host suffix, or userinfo in the URL. The admin form writes
// each value into the server URL; the catalog OAuth templates keep the
// placeholder and connect reads the value back from that URL. A secret
// credential is not required here. A catalog code with no such variable, or
// a target that is not a catalog entry, is left alone.
func RequireAdminBoundURLVariables(target *domain.MCPTarget, catalog MCPAuthCatalog) error {
	if target == nil || catalog == nil {
		return nil
	}
	code := strings.TrimSpace(target.Code)
	if code == "" {
		return nil
	}
	entry, ok := catalog.GetByCode(code)
	if !ok {
		return nil
	}
	vars := catalogURLVarsAsRegistry(entry.URLVariables)
	if err := domain.RejectURLUserinfo(target.URL); err != nil {
		return fmt.Errorf("%w: %w", commonerrors.ErrValidation, err)
	}
	admin, matched := domain.AdminBoundValues(entry.URL, vars, target.URL)
	if strings.Contains(entry.URL, "{") && strings.TrimSpace(target.URL) != "" && !matched {
		return fmt.Errorf("%w: registry URL does not match the catalog template", commonerrors.ErrValidation)
	}
	var missing []string
	values := make(map[string]string)
	var check []domain.MCPURLVariable
	for _, variable := range vars {
		if variable.Secret {
			continue
		}
		val := ""
		if matched {
			val = strings.TrimSpace(admin[variable.Name])
		}
		if val == "" {
			if variable.Required && !target.PinsURLVariable(variable.Name) {
				missing = append(missing, variable.Name)
			}
			continue
		}
		values[variable.Name] = val
		check = append(check, variable)
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: registry variable %s must be set on the registry", commonerrors.ErrValidation, strings.Join(missing, ", "))
	}
	if len(check) == 0 {
		return nil
	}
	if err := domain.ValidateURLValues(check, values); err != nil {
		return fmt.Errorf("%w: %w", commonerrors.ErrValidation, err)
	}
	if err := domain.ValidateHostSuffixes(check, values); err != nil {
		return fmt.Errorf("%w: %w", commonerrors.ErrValidation, err)
	}
	return nil
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
	bindSharedOAuth(target, catalog)
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
	// A row saved while this server required a manual client already has a
	// client id. The catalog may since have switched to dynamic registration
	// (Dropbox, Jotform). Forcing auto here makes Validate reject the row,
	// because auto does not accept client_id, and the admin would have to
	// clear the client id to save any other edit. Keep the stored client on
	// manual registration. A save that carries no client id still follows the
	// catalog and becomes auto.
	if target.Auth.Registration == domain.RegistrationAuto && strings.TrimSpace(target.Auth.ClientID) != "" {
		target.Auth.Registration = domain.RegistrationManual
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
	assignCatalogResource(target, entry)
	return nil
}

// assignCatalogResource copies the catalog audience onto the row. A templated
// audience is stored as the concrete resource the target URL resolves to, using
// the same closed-option match as connect. A concrete resource already on the
// row is left in place when that match is not unique: replacing it with the
// template would change the vault fingerprint and orphan every stored token.
func assignCatalogResource(target *domain.MCPTarget, entry catalogdomain.MCPServer) {
	if target == nil || target.Auth == nil || entry.OAuth == nil {
		return
	}
	resource := strings.TrimSpace(entry.OAuth.Resource)
	stored := strings.TrimSpace(target.Auth.Resource)
	// Only a catalog resource that is itself a template is per-instance.
	// Copying a templated server URL into the row (resource_metadata) must
	// not flip this: New Relic and Vanta tokens are stored under that template.
	target.Auth.ResourcePerInstance = strings.Contains(resource, "{")
	templated := strings.Contains(resource, "{") || (resource == "" && entry.OAuth.ResourceMetadata && strings.Contains(target.URL, "{"))
	if templated {
		if concrete, ok := concreteCatalogResource(target, entry, resource); ok {
			target.Auth.Resource = concrete
			return
		}
		if stored != "" && !strings.ContainsAny(stored, "{}") {
			return
		}
	}
	switch {
	case resource != "":
		target.Auth.Resource = resource
	case entry.OAuth.ResourceMetadata && stored == "":
		target.Auth.Resource = target.URL
	}
}

// concreteCatalogResource resolves a templated catalog resource against the
// target URL. It succeeds only when exactly one closed option produces that
// URL, so an open host and an ambiguous option list never invent an audience.
func concreteCatalogResource(target *domain.MCPTarget, entry catalogdomain.MCPServer, resource string) (string, bool) {
	if target == nil {
		return "", false
	}
	vars := catalogURLVarsAsRegistry(entry.URLVariables)
	values, ok := domain.ClosedOptionMatch(entry.URL, vars, nil, target.URL)
	if !ok {
		return "", false
	}
	template := resource
	if template == "" {
		template = strings.TrimSpace(entry.URL)
	}
	if template == "" || !strings.Contains(template, "{") {
		if template == "" {
			return "", false
		}
		return template, true
	}
	resolved, err := domain.ResolveURL(template, vars, values)
	if err != nil || strings.ContainsAny(resolved, "{}") {
		return "", false
	}
	return resolved, true
}

func catalogURLVarsAsRegistry(vars []catalogdomain.MCPURLVariable) []domain.MCPURLVariable {
	if len(vars) == 0 {
		return nil
	}
	out := make([]domain.MCPURLVariable, 0, len(vars))
	for _, variable := range vars {
		converted := domain.MCPURLVariable{
			Name:        strings.TrimSpace(variable.Name),
			Description: variable.Description,
			Required:    variable.Required,
			Secret:      variable.Secret,
			In:          strings.TrimSpace(variable.In),
			HostSuffix:  append([]string(nil), variable.HostSuffix...),
		}
		for _, option := range variable.Options {
			converted.Options = append(converted.Options, domain.MCPURLVariableOption{
				Value: strings.TrimSpace(option.Value),
				Label: option.Label,
			})
		}
		out = append(out, converted)
	}
	return out
}

// bindSharedOAuth points a forwarded target at the platform's shared OAuth
// client by its id alone. The client secret is not stored on the registry: the
// connect and refresh paths read it from the platform configuration each time
// they present the client, and only to the provider's own endpoints, so binding
// the id needs no endpoint check of its own. It reports whether the target
// changed.
func bindSharedOAuth(target *domain.MCPTarget, catalog MCPAuthCatalog) bool {
	if target == nil || target.Auth == nil || catalog == nil {
		return false
	}
	if target.Auth.Mode != domain.MCPAuthModeForwarded {
		return false
	}
	if target.Auth.Registration == domain.RegistrationAuto {
		return false
	}
	creds, ok := mcpoauth.SharedClientFor(sharedOAuthProvider(catalog), mcpoauth.SharedClientQuery{
		Code:     target.Code,
		Provider: target.Auth.Provider,
		ClientID: target.Auth.ClientID,
	})
	if !ok {
		return false
	}
	changed := target.Auth.ClientID != creds.ClientID || target.Auth.ClientSecret != ""
	target.Auth.ClientID = creds.ClientID
	target.Auth.ClientSecret = ""
	return changed
}

func sharedOAuthProvider(catalog MCPAuthCatalog) mcpoauth.Provider {
	return mcpoauth.ProviderFunc(func(code string) (mcpoauth.Credentials, bool) {
		id, secret, ok := catalog.SharedOAuthCredentials(code)
		return mcpoauth.Credentials{ClientID: id, ClientSecret: secret}, ok
	})
}
