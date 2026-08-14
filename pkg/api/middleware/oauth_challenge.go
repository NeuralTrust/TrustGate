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

type OAuthChallengeMiddleware struct{}

func NewOAuthChallengeMiddleware() *OAuthChallengeMiddleware {
	return &OAuthChallengeMiddleware{}
}

func (m *OAuthChallengeMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		err := c.Next()
		if isUnauthorized(c, err) {
			c.Set(fiber.HeaderWWWAuthenticate, bearerChallenge(c))
		}
		return err
	}
}

// bearerChallenge builds an RFC 9728 challenge whose resource_metadata points at
// the protected-resource document scoped to the requested MCP path, so clients
// send an RFC 8707 resource that identifies the consumer and its identity
// provider rather than the gateway root.
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
