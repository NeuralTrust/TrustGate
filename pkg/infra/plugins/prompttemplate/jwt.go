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

package prompttemplate

import (
	"encoding/json"
	"strconv"
	"strings"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/golang-jwt/jwt/v5"
)

func bearerToken(req *infracontext.RequestContext) string {
	header := req.HeaderValue("Authorization")
	if header == "" {
		return ""
	}
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

// unverifiedClaim reads a claim WITHOUT checking the token's signature.
//
// The value is only as trustworthy as the caller's authentication method. The
// auth chain resolves identity from mTLS, then a bearer token, then an api key
// (middleware/auth_chain.go), so a consumer authenticating by api key or mTLS can
// send any Authorization header it likes and this will read whatever it put
// there. Claims are trustworthy only when bearer auth is what admitted the
// caller, and a claim must not be used for an authorization decision otherwise.
//
// Verifying here is not an option while this plugin stays previewable: signature
// checks need the gateway's auth configuration and, for a remote JWKS, the
// network — which is exactly what Previewable (app/plugins/plugin.go) forbids.
// The honest fix is to carry already-verified claims on the request context.
func unverifiedClaim(token, claimName string) (string, bool) {
	if token == "" || claimName == "" {
		return "", false
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return "", false
	}
	raw, ok := claims[claimName]
	if !ok {
		return "", false
	}
	switch v := raw.(type) {
	case string:
		return v, true
	case json.Number:
		return v.String(), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	default:
		return "", false
	}
}
