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
)

// forwardedVaultSeparator joins the provider name and the resource fingerprint
// in a vault key. It cannot occur in a provider name (a catalog code), so the
// two halves are never ambiguous.
const forwardedVaultSeparator = "|"

// forwardedResourceFingerprintLen keeps the key short while leaving collisions
// out of reach: 48 bits of a SHA-256 over a URL, within one gateway.
const forwardedResourceFingerprintLen = 12

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
// A URL still carrying `{placeholders}` fingerprints as written. Every vault key
// is already per principal, so a template resolved differently per user needs no
// further separation here.
func ForwardedCredentialResource(reg *Registry) string {
	cfg := reg.ForwardedAuth()
	if cfg == nil {
		return ""
	}
	if resource := strings.TrimSpace(cfg.Resource); resource != "" {
		return canonicalResource(resource)
	}
	return canonicalResource(reg.MCPTarget.URL)
}

// ForwardedVaultProvider is the vault "provider" key a registry's forwarded
// OAuth credential is stored under: the provider name plus a fingerprint of the
// resource ForwardedCredentialResource resolves.
//
// Every reader and writer of such a credential derives its key here, and the
// dynamically registered OAuth client is cached under the same key (see
// appoauth.clientKey): a refresh token can only be redeemed by the client it
// was issued to, so the credential and that client must never be keyed apart.
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
