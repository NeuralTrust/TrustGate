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

package middleware_test

import (
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/gofiber/fiber/v2"
)

func TestSecurityHeaders_ReferrerPolicy(t *testing.T) {
	t.Parallel()
	app := fiber.New()
	app.Use(middleware.NewSecurityHeadersMiddleware().Middleware())
	app.Get("/default", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })
	app.Get("/own", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderReferrerPolicy, "same-origin")
		return c.SendStatus(fiber.StatusOK)
	})
	for path, want := range map[string]string{"/default": "no-referrer", "/own": "same-origin"} {
		res, err := app.Test(httptest.NewRequest(fiber.MethodGet, path, nil))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if got := res.Header.Get(fiber.HeaderReferrerPolicy); got != want {
			t.Fatalf("%s: Referrer-Policy = %q, want %q", path, got, want)
		}
		if res.Header.Get("X-Frame-Options") != "DENY" {
			t.Fatalf("%s: X-Frame-Options missing", path)
		}
	}
}
