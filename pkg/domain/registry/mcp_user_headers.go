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
	"net/http"
	"regexp"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// MCPUserHeader declares one upstream header whose value belongs to each
// caller rather than to the registry. The admin declares the header; every
// person enrolls their own value once, through the connect link, and the
// gateway sends the calling person's value on each request to the upstream.
// Values live in the vault under the registry instance and the caller's
// principal (UserHeaderVaultProvider), never on the registry row.
type MCPUserHeader struct {
	// Name is the HTTP header sent upstream, e.g. X-API-Key.
	Name string `json:"name"`
	// Description is the help shown when a person enters their value.
	Description string `json:"description,omitempty"`
	// Required makes a call fail with a connect link until the caller has a
	// value. An optional header is simply left out when the caller has none.
	Required bool `json:"required,omitempty"`
	// Secret hides the value once entered: the connect page shows it masked
	// and it is never echoed back. A non-secret value (an account id, a
	// tenant) is shown back to its owner so it can be checked and edited.
	// Both are stored encrypted in the vault.
	Secret bool `json:"secret,omitempty"`
	// Scheme is written before the value with one space, e.g. "Bearer" sends
	// "Bearer <value>". Empty sends the value as entered.
	Scheme string `json:"scheme,omitempty"`
}

// MaxUserHeaderValueLen bounds one per-user header value. An API key or a
// token fits comfortably; anything longer is not a credential a person typed.
const MaxUserHeaderValueLen = 4096

// maxUserHeaders bounds how many per-user headers one registry declares.
const maxUserHeaders = 16

// userHeaderVaultPrefix namespaces per-user header values in the vault, apart
// from forwarded OAuth credentials and secret URL variables.
const userHeaderVaultPrefix = "uhdr:"

// httpToken is an RFC 9110 token: what a header name and an auth scheme are.
var httpToken = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

// reservedUpstreamHeaders are names a per-user value may never set: the
// transport owns them, the MCP protocol owns them, or a hop strips them.
var reservedUpstreamHeaders = []string{
	"Host", "Content-Length", "Content-Type", "Content-Encoding", "Transfer-Encoding",
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Proxy-Connection", "TE", "Trailer", "Upgrade", "Cookie", "Accept",
	"Mcp-Session-Id", "Mcp-Protocol-Version", "Last-Event-ID",
}

// reservedUpstreamHeaderPrefix is the gateway's own header namespace.
const reservedUpstreamHeaderPrefix = "x-neuraltrust-"

// UserHeaderVaultProvider is the vault "provider" key a person's value for one
// per-user header of one registry instance is stored under. It is keyed by the
// registry, not by the catalog code, so two instances of the same upstream
// (PRE and PRO) hold separate values while one instance bound to several
// applications reads the same value. The header name is canonicalised so the
// writer and the reader agree whatever case the admin typed.
func UserHeaderVaultProvider(registryID ids.RegistryID, header string) string {
	return userHeaderVaultPrefix + registryID.String() + ":" + http.CanonicalHeaderKey(strings.TrimSpace(header))
}

// UserHeaderVaultPrefix is the vault provider prefix every per-user header of
// one registry shares, for listing or resetting all of them at once.
func UserHeaderVaultPrefix(registryID ids.RegistryID) string {
	return userHeaderVaultPrefix + registryID.String() + ":"
}

// HasUserHeaders reports whether any upstream header of this target is
// resolved per caller.
func (t *MCPTarget) HasUserHeaders() bool {
	return t != nil && len(t.UserHeaders) > 0
}

// UserHeader returns the declared per-user header with this name, matched
// case-insensitively as HTTP header names are.
func (t *MCPTarget) UserHeader(name string) (MCPUserHeader, bool) {
	if t == nil {
		return MCPUserHeader{}, false
	}
	for _, h := range t.UserHeaders {
		if strings.EqualFold(strings.TrimSpace(h.Name), strings.TrimSpace(name)) {
			return h, true
		}
	}
	return MCPUserHeader{}, false
}

// FormatValue is the header value sent upstream for a person's stored value.
func (h MCPUserHeader) FormatValue(value string) string {
	if scheme := strings.TrimSpace(h.Scheme); scheme != "" {
		return scheme + " " + value
	}
	return value
}

// ValidateUserHeaderValue checks a value a person enters for a per-user
// header. It never echoes the value: the error names the header only.
func ValidateUserHeaderValue(h MCPUserHeader, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: header %q needs a value", ErrInvalidMCPTarget, h.Name)
	}
	if len(value) > MaxUserHeaderValueLen {
		return fmt.Errorf("%w: header %q value is too long (max %d characters)", ErrInvalidMCPTarget, h.Name, MaxUserHeaderValueLen)
	}
	for _, r := range value {
		// Visible ASCII and space/tab only: CR, LF and NUL would split the
		// request, and anything else is not a value an HTTP header carries
		// reliably.
		if r == '\t' || (r >= 0x20 && r < 0x7f) {
			continue
		}
		return fmt.Errorf("%w: header %q value has characters an HTTP header cannot carry", ErrInvalidMCPTarget, h.Name)
	}
	return nil
}

// validateUserHeaders checks the per-user header declarations against each
// other, against the shared headers and against whatever the auth mode sends.
func (t *MCPTarget) validateUserHeaders() error {
	if len(t.UserHeaders) == 0 {
		return nil
	}
	if len(t.UserHeaders) > maxUserHeaders {
		return fmt.Errorf("%w: at most %d per-user headers", ErrInvalidMCPTarget, maxUserHeaders)
	}
	authHeader := t.authSetsHeader()
	seen := make(map[string]struct{}, len(t.UserHeaders))
	for _, h := range t.UserHeaders {
		name := strings.TrimSpace(h.Name)
		if name == "" || !httpToken.MatchString(name) {
			return fmt.Errorf("%w: per-user header name %q is not a valid HTTP header name", ErrInvalidMCPTarget, h.Name)
		}
		if IsReservedUpstreamHeader(name) {
			return fmt.Errorf("%w: header %q is reserved and cannot be set per user", ErrInvalidMCPTarget, name)
		}
		key := strings.ToLower(name)
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%w: per-user header %q is declared twice", ErrInvalidMCPTarget, name)
		}
		seen[key] = struct{}{}
		if _, shared := storedHeader(t.Headers, name); shared {
			return fmt.Errorf("%w: header %q is both shared and per-user; pick one", ErrInvalidMCPTarget, name)
		}
		if authHeader != "" && strings.EqualFold(authHeader, name) {
			return fmt.Errorf("%w: header %q is already set by auth mode %q", ErrInvalidMCPTarget, name, t.Auth.Mode)
		}
		if scheme := strings.TrimSpace(h.Scheme); scheme != "" && !httpToken.MatchString(scheme) {
			return fmt.Errorf("%w: per-user header %q scheme %q is not a valid token", ErrInvalidMCPTarget, name, h.Scheme)
		}
		if len(h.Description) > 512 {
			return fmt.Errorf("%w: per-user header %q description is too long", ErrInvalidMCPTarget, name)
		}
	}
	return nil
}

// authSetsHeader names the header the auth mode writes on every upstream
// call, or "" when it writes none.
func (t *MCPTarget) authSetsHeader() string {
	if t.Auth == nil {
		return ""
	}
	switch t.Auth.Mode {
	case MCPAuthModeStatic:
		return strings.TrimSpace(t.Auth.Header)
	case MCPAuthModePassthrough, MCPAuthModeExchange, MCPAuthModeForwarded, MCPAuthModeClientCredentials:
		return "Authorization"
	default:
		return ""
	}
}

// IsReservedUpstreamHeader reports whether name is a header the gateway, the
// transport or the MCP protocol owns, so no per-user value may set it.
func IsReservedUpstreamHeader(name string) bool {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(strings.ToLower(name), reservedUpstreamHeaderPrefix) {
		return true
	}
	for _, r := range reservedUpstreamHeaders {
		if strings.EqualFold(r, name) {
			return true
		}
	}
	return false
}
