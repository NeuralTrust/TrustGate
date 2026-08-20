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

package middleware

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
)

const protectedResourceMetadataPath = "/.well-known/oauth-protected-resource"

// OAuthChallengeModeLocal is the request-local key for OAuthChallengeMode.
const OAuthChallengeModeLocal = "trustgate.oauth.challenge.mode"

// OAuthChallengeMode selects how a 401 response is challenged.
type OAuthChallengeMode int

const (
	// OAuthChallengeAdvertise is the zero value, so a request whose mode was
	// never recorded keeps advertising protected-resource metadata.
	OAuthChallengeAdvertise OAuthChallengeMode = iota
	OAuthChallengeDiagnostic
	OAuthChallengeSilent
)

const missingBrokerClientDescription = "the identity provider configured for this resource has no pre-registered client_id, " +
	"so this gateway cannot broker an interactive login; present an access token obtained directly from that identity provider"

type OAuthChallengeMiddleware struct{}

func NewOAuthChallengeMiddleware() *OAuthChallengeMiddleware {
	return &OAuthChallengeMiddleware{}
}

func (m *OAuthChallengeMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		err := c.Next()
		if !isUnauthorized(c, err) {
			return err
		}
		switch oauthChallengeMode(c) {
		case OAuthChallengeAdvertise:
			c.Set(fiber.HeaderWWWAuthenticate, bearerChallenge(c))
		case OAuthChallengeDiagnostic:
			c.Set(fiber.HeaderWWWAuthenticate, diagnosticChallenge())
		case OAuthChallengeSilent:
			return err
		}
		return err
	}
}

func oauthChallengeMode(c *fiber.Ctx) OAuthChallengeMode {
	mode, known := c.Locals(OAuthChallengeModeLocal).(OAuthChallengeMode)
	if !known {
		return OAuthChallengeAdvertise
	}
	return mode
}

func diagnosticChallenge() string {
	return `Bearer error="invalid_request", error_description="` + missingBrokerClientDescription + `"`
}

func bearerChallenge(c *fiber.Ctx) string {
	metadata := c.BaseURL() + protectedResourceMetadataPath
	if resourcePath := strings.Trim(c.Path(), "/"); resourcePath != "" {
		metadata += "/" + resourcePath
	}
	return `Bearer resource_metadata="` + metadata + `"`
}

func isUnauthorized(c *fiber.Ctx, err error) bool {
	var fe *fiber.Error
	if errors.As(err, &fe) {
		return fe.Code == fiber.StatusUnauthorized
	}
	return err == nil && c.Response().StatusCode() == fiber.StatusUnauthorized
}
