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

package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
)

const gatewayRefreshPrefix = "gwrt_"

func clientRedirect(redirectURI string, params url.Values, state string) string {
	if state != "" {
		params.Set("state", state)
	}
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	return redirectURI + sep + params.Encode()
}

func mergeScopes(requested string, required []string) string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range append(strings.Fields(requested), required...) {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return strings.Join(out, " ")
}

// upstreamScopes sends the operator's login scopes instead of the client's
// request: MCP clients ask for the short form the token carries (Entra puts
// "mcp.access" in scp), which Entra reads as a Microsoft Graph scope at
// /authorize. Only the client's protocol scopes are kept alongside them.
func upstreamScopes(cfg *authdomain.OAuth2Config, requested string) string {
	if len(cfg.LoginScopes) == 0 {
		return mergeScopes(requested, cfg.RequiredScopes)
	}
	var protocol []string
	for _, s := range strings.Fields(requested) {
		if identity.IsProtocolScope(s) {
			protocol = append(protocol, s)
		}
	}
	return mergeScopes(strings.Join(cfg.LoginScopes, " "), protocol)
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", errors.New("oauth: entropy unavailable")
	}
	return hex.EncodeToString(buf), nil
}
