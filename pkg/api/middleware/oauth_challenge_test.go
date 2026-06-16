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
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestOAuthChallengeAddsWWWAuthenticateOn401(t *testing.T) {
	t.Parallel()
	app := fiber.New()
	app.Use(NewOAuthChallengeMiddleware().Middleware())
	app.Post("/v1/mcp/dev", func(c *fiber.Ctx) error {
		return fiber.NewError(fiber.StatusUnauthorized, "unauthenticated")
	})

	res, err := app.Test(httptest.NewRequest(fiber.MethodPost, "http://gw.example.com/v1/mcp/dev", nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.StatusCode)
	}
	challenge := res.Header.Get(fiber.HeaderWWWAuthenticate)
	if !strings.HasPrefix(challenge, "Bearer ") {
		t.Fatalf("expected Bearer challenge, got %q", challenge)
	}
	if !strings.Contains(challenge, `resource_metadata="http://gw.example.com/.well-known/oauth-protected-resource"`) {
		t.Fatalf("expected resource_metadata pointer, got %q", challenge)
	}
}

func TestOAuthChallengeSkipsNon401(t *testing.T) {
	t.Parallel()
	app := fiber.New()
	app.Use(NewOAuthChallengeMiddleware().Middleware())
	app.Post("/v1/mcp/dev", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	res, err := app.Test(httptest.NewRequest(fiber.MethodPost, "http://gw.example.com/v1/mcp/dev", nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := res.Header.Get(fiber.HeaderWWWAuthenticate); got != "" {
		t.Fatalf("expected no challenge, got %q", got)
	}
}

func TestOAuthChallengeOnDirectStatus401(t *testing.T) {
	t.Parallel()
	app := fiber.New()
	app.Use(NewOAuthChallengeMiddleware().Middleware())
	app.Post("/v1/mcp/dev", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusUnauthorized)
	})

	res, err := app.Test(httptest.NewRequest(fiber.MethodPost, "http://gw.example.com/v1/mcp/dev", nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := res.Header.Get(fiber.HeaderWWWAuthenticate); !strings.Contains(got, "resource_metadata=") {
		t.Fatalf("expected challenge on direct 401 status, got %q", got)
	}
}
