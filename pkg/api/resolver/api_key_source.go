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

package resolver

import (
	"strings"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/gofiber/fiber/v2"
)

// HeaderAPIKeyCompat is the Anthropic-style header some OpenAI-compatible
// clients (Claude Code, etc.) use when they can only send an api key and not
// custom headers.
const HeaderAPIKeyCompat = "x-api-key"

// APIKeyFromRequest returns the gateway api key presented by the caller, or
// an empty string when none is present. Precedence is X-AG-API-Key, then
// x-api-key, then Authorization: Bearer when the token carries the TrustGate
// api-key prefix. A bearer without that prefix is left for OAuth2/OIDC.
func APIKeyFromRequest(c *fiber.Ctx) string {
	if key := strings.TrimSpace(c.Get(HeaderAPIKey)); key != "" {
		return key
	}
	if key := strings.TrimSpace(c.Get(HeaderAPIKeyCompat)); key != "" {
		return key
	}
	token, err := bearerToken(c.Get(fiber.HeaderAuthorization))
	if err != nil {
		return ""
	}
	if !authdomain.HasAPIKeyPrefix(token) {
		return ""
	}
	return token
}
