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

	req := httptest.NewRequest(fiber.MethodPost, "/v1/mcp/dev", nil)
	req.Host = "gw.example.com"
	res, err := app.Test(req)
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
	if !strings.Contains(challenge, `resource_metadata="http://gw.example.com/.well-known/oauth-protected-resource/v1/mcp/dev"`) {
		t.Fatalf("expected path-scoped resource_metadata pointer, got %q", challenge)
	}
}

func TestOAuthChallengeUsesRootMetadataForRootPath(t *testing.T) {
	t.Parallel()
	app := fiber.New()
	app.Use(NewOAuthChallengeMiddleware().Middleware())
	app.Post("/", func(c *fiber.Ctx) error {
		return fiber.NewError(fiber.StatusUnauthorized, "unauthenticated")
	})

	req := httptest.NewRequest(fiber.MethodPost, "/", nil)
	req.Host = "gw.example.com"
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	challenge := res.Header.Get(fiber.HeaderWWWAuthenticate)
	if !strings.Contains(challenge, `resource_metadata="http://gw.example.com/.well-known/oauth-protected-resource"`) {
		t.Fatalf("expected root resource_metadata pointer, got %q", challenge)
	}
}

func TestOAuthChallengeSkipsNon401(t *testing.T) {
	t.Parallel()
	app := fiber.New()
	app.Use(NewOAuthChallengeMiddleware().Middleware())
	app.Post("/v1/mcp/dev", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(fiber.MethodPost, "/v1/mcp/dev", nil)
	req.Host = "gw.example.com"
	res, err := app.Test(req)
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

	req := httptest.NewRequest(fiber.MethodPost, "/v1/mcp/dev", nil)
	req.Host = "gw.example.com"
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := res.Header.Get(fiber.HeaderWWWAuthenticate); !strings.Contains(got, "resource_metadata=") {
		t.Fatalf("expected challenge on direct 401 status, got %q", got)
	}
}

func TestOAuthChallengeUsesTriStateEligibility(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		eligibility any
		want        bool
	}{
		{name: "unknown preserves challenge", want: true},
		{name: "allowed challenges", eligibility: true, want: true},
		{name: "disallowed suppresses challenge", eligibility: false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			app := fiber.New()
			app.Use(NewOAuthChallengeMiddleware().Middleware())
			app.Post("/v1/mcp/dev", func(c *fiber.Ctx) error {
				if tt.eligibility != nil {
					c.Locals(OAuthChallengeAllowedLocal, tt.eligibility)
				}
				return fiber.NewError(fiber.StatusUnauthorized, "unauthenticated")
			})

			res, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/v1/mcp/dev", nil))
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			got := res.Header.Get(fiber.HeaderWWWAuthenticate) != ""
			if got != tt.want {
				t.Fatalf("challenge present = %t, want %t", got, tt.want)
			}
		})
	}
}
