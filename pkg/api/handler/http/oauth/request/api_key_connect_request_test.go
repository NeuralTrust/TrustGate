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

package request

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestAPIKeyConnectRequest_DecodesOnlyFormField(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		body     string
		header   string
		expected string
	}{
		{
			name:     "form body",
			target:   "/decode",
			body:     "api_key=body-secret",
			expected: "body-secret",
		},
		{
			name:   "query is ignored",
			target: "/decode?api_key=query-secret",
			body:   "other=value",
		},
		{
			name:   "header is ignored",
			target: "/decode",
			body:   "other=value",
			header: "header-secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := fiber.New()
			var decoded APIKeyConnectRequest
			app.Post("/decode", func(c *fiber.Ctx) error {
				if err := c.BodyParser(&decoded); err != nil {
					return err
				}
				return c.SendStatus(fiber.StatusNoContent)
			})

			req := httptest.NewRequest("POST", tt.target, strings.NewReader(tt.body))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationForm)
			if tt.header != "" {
				req.Header.Set("X-AG-API-Key", tt.header)
			}
			res, err := app.Test(req)
			if err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if res.StatusCode != fiber.StatusNoContent {
				t.Fatalf("status = %d, want %d", res.StatusCode, fiber.StatusNoContent)
			}
			if decoded.APIKey != tt.expected {
				t.Fatalf("APIKey = %q, want %q", decoded.APIKey, tt.expected)
			}
		})
	}
}
