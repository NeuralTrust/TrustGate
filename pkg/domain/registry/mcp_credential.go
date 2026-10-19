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
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// forwardedVaultSeparator joins the provider name and the resource fingerprint
// in a vault key. It cannot occur in a provider name (a catalog code), so the
// two halves are never ambiguous.
const forwardedVaultSeparator = "|"

// forwardedResourceFingerprintLen keeps the key short while leaving collisions
// out of reach: 48 bits of a SHA-256 over a URL, within one gateway.
const forwardedResourceFingerprintLen = 12

// sharedAccountSubjectPrefix namespaces the account an instance holds for
// everyone, so it can never collide with a person's token subject or with an
// application's own (app:<consumer_id>).
const sharedAccountSubjectPrefix = identity.InstanceSubjectPrefix

// Shared reports whether one connected account serves every caller of this
// instance, rather than each caller connecting their own.
func (a *MCPAuth) Shared() bool {
	return a != nil && a.Mode == MCPAuthModeForwarded && a.Account == MCPAccountShared
}

// SharedAccountSubject is the vault subject an instance's shared account is
// stored under. The instance, not the catalog code: two instances of one
// server are two accounts — that is what having two instances is for.
func SharedAccountSubject(registryID ids.RegistryID) string {
	return sharedAccountSubjectPrefix + registryID.String()
}

// CredentialSubject is whose forwarded credential a call on this registry
// reads: the caller's own account, or the one the instance holds for everyone.
func CredentialSubject(reg *Registry, principalSub string) string {
	if reg != nil && reg.ForwardedAuth().Shared() {
		return SharedAccountSubject(reg.ID)
	}
	return principalSub
}

// ForwardedAuth returns the registry's forwarded OAuth config, or nil when the
// registry does not forward a per-user credential.
func (r *Registry) ForwardedAuth() *MCPAuth {
	if r == nil || !r.IsMCP() || r.MCPTarget == nil || r.MCPTarget.Auth == nil {
		return nil
	}
	if r.MCPTarget.Auth.Mode != MCPAuthModeForwarded {
		return nil
	}
	return r.MCPTarget.Auth
}

// ForwardedCredentialResource is the upstream deployment a forwarded credential
// belongs to: the auth config's OAuth resource when it declares one, else the
// server's own URL (which is the protected resource a DCR flow discovers from).
//
// It is what tells two instances of the same catalog code apart. Two registries
// pointing at the same deployment — the same Linear workspace with different
// toolkits, say — share a resource and therefore a credential, so the user
// connects once. Two instances pointing at different workspaces do not, and
// each is connected on its own; sharing there would forward a token minted for
// one tenant to another.
//
// A catalog resource marked per-instance is filled from this registry's
// instance config when every placeholder is a closed option, so two regions
// of that catalog code do not share a token. Anything else — an open
// placeholder, a shared account, a resource the catalog did not declare as
// per-instance — stays written. New Relic and Vanta rows, including one an
// admin saved with their own client, keep the template fingerprint their
// tokens were stored under. An empty resource falls back to the server URL
// and is fingerprinted the same way.
func ForwardedCredentialResource(reg *Registry) string {
	cfg := reg.ForwardedAuth()
	if cfg == nil {
		return ""
	}
	resource := strings.TrimSpace(cfg.Resource)
	if resource == "" && reg.MCPTarget != nil {
		resource = strings.TrimSpace(reg.MCPTarget.URL)
	} else if resolved, ok := resolvedClosedResource(reg, resource); ok {
		return canonicalResource(resolved)
	}
	return canonicalResource(resource)
}

// resolvedClosedResource fills resource from instance config when the catalog
// marked it per-instance and every placeholder is a closed option with a
// value. A shared account is never filled: the one token is saved and read
// under the stored resource. Anything else returns false and the caller
// fingerprints resource as written.
func resolvedClosedResource(reg *Registry, resource string) (string, bool) {
	if reg == nil || reg.MCPTarget == nil || reg.MCPTarget.Auth == nil || !strings.Contains(resource, "{") {
		return "", false
	}
	if !reg.MCPTarget.Auth.ResourcePerInstance || reg.MCPTarget.Auth.Shared() {
		return "", false
	}
	names := TemplateVariableNames(resource)
	if len(names) == 0 {
		return "", false
	}
	declared := make(map[string]MCPURLVariable, len(reg.MCPTarget.URLVariables))
	for _, variable := range reg.MCPTarget.URLVariables {
		declared[variable.Name] = variable
	}
	values := make(map[string]string, len(names))
	for _, name := range names {
		variable, known := declared[name]
		if !known || !variable.HasOptions() {
			return "", false
		}
		val := strings.TrimSpace(reg.MCPTarget.InstanceConfig[name])
		if val == "" || !variable.AllowsValue(val) {
			return "", false
		}
		values[name] = val
	}
	resolved, err := ResolveURL(resource, reg.MCPTarget.URLVariables, values)
	if err != nil || strings.ContainsAny(resolved, "{}") {
		return "", false
	}
	return resolved, true
}

// RegistryWithInstanceConfig returns a clone whose target carries values as
// its instance config. The caller's registry is not modified. A registry that
// already has instance config, or an empty value map, is returned as given.
func RegistryWithInstanceConfig(reg *Registry, values map[string]string) *Registry {
	if reg == nil || reg.MCPTarget == nil || len(reg.MCPTarget.InstanceConfig) > 0 || len(values) == 0 {
		return reg
	}
	cp := *reg
	target := *reg.MCPTarget
	cfg := make(map[string]string, len(values))
	for key, value := range values {
		cfg[key] = value
	}
	target.InstanceConfig = cfg
	cp.MCPTarget = &target
	return &cp
}

// ForwardedVaultProviderFor is the vault key for reg. config is a per-user
// install's plain URL values and is applied only when the registry does not
// already carry instance config. A shared account ignores config. Every
// reader and writer of a forwarded credential goes through this function.
func ForwardedVaultProviderFor(reg *Registry, config map[string]string) string {
	if auth := reg.ForwardedAuth(); auth != nil && auth.Shared() {
		return ForwardedVaultProvider(reg)
	}
	if len(config) > 0 {
		reg = RegistryWithInstanceConfig(reg, config)
	}
	return ForwardedVaultProvider(reg)
}

// ForwardedVaultProvider is the vault "provider" key a registry's forwarded
// OAuth credential is stored under: the provider name plus a fingerprint of the
// resource ForwardedCredentialResource resolves. Callers that hold a per-user
// install use ForwardedVaultProviderFor so the key matches connect and dial.
//
// Every reader and writer of such a credential derives its key here. The
// dynamically registered OAuth client is cached under this same fingerprint
// plus the authorization server it was registered with (see appoauth.clientKey):
// a refresh token can only be redeemed by the client it was issued to, and two
// hosts that resolve one template must not share that client.
//
// Empty when the registry forwards nothing, or names no provider.
func ForwardedVaultProvider(reg *Registry) string {
	cfg := reg.ForwardedAuth()
	if cfg == nil {
		return ""
	}
	provider := strings.TrimSpace(cfg.Provider)
	if provider == "" {
		return ""
	}
	resource := ForwardedCredentialResource(reg)
	if resource == "" {
		return provider
	}
	sum := sha256.Sum256([]byte(resource))
	return provider + forwardedVaultSeparator + hex.EncodeToString(sum[:])[:forwardedResourceFingerprintLen]
}

// ForwardedVaultProviderName is the provider name inside a vault key built by
// ForwardedVaultProvider — what the connect page's callback path and the brand
// logo are keyed on. A key with no fingerprint is returned unchanged.
func ForwardedVaultProviderName(vaultProvider string) string {
	if idx := strings.Index(vaultProvider, forwardedVaultSeparator); idx >= 0 {
		return vaultProvider[:idx]
	}
	return vaultProvider
}

// canonicalResource normalizes the parts of a URL that carry no meaning for
// "is this the same deployment": the scheme and host case, a default port, a
// trailing slash and any fragment. Anything unparseable is used as written.
func canonicalResource(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" {
		return strings.TrimRight(trimmed, "/")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	if port := parsed.Port(); (parsed.Scheme == "https" && port == "443") ||
		(parsed.Scheme == "http" && port == "80") {
		parsed.Host = parsed.Hostname()
	}
	parsed.Fragment = ""
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed.String()
}

// SameCanonicalResource reports whether two resource identifiers name the same
// protected resource. Comparison uses canonicalResource: scheme and host case,
// a default port, a trailing slash, and any fragment. Empty values are not the
// same resource.
func SameCanonicalResource(a, b string) bool {
	left, right := canonicalResource(a), canonicalResource(b)
	return left != "" && left == right
}
