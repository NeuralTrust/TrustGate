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

	"github.com/gofiber/fiber/v2"
)

type OAuthChallengeMiddleware struct{}

func NewOAuthChallengeMiddleware() *OAuthChallengeMiddleware {
	return &OAuthChallengeMiddleware{}
}

func (m *OAuthChallengeMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		err := c.Next()
		if isUnauthorized(c, err) {
			c.Set(fiber.HeaderWWWAuthenticate,
				`Bearer resource_metadata="`+c.BaseURL()+`/.well-known/oauth-protected-resource"`)
		}
		return err
	}
}

func isUnauthorized(c *fiber.Ctx, err error) bool {
	var fe *fiber.Error
	if errors.As(err, &fe) {
		return fe.Code == fiber.StatusUnauthorized
	}
	return err == nil && c.Response().StatusCode() == fiber.StatusUnauthorized
}
