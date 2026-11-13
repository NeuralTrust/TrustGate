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

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appsecretstore "github.com/NeuralTrust/TrustGate/pkg/app/secretstore"
)

// TestStoredIdentityCarriesTheSecretRefCaller pins that every admin route,
// not only registry writes, hands the reference validator its caller: a
// console user may reference, a service credential only with the scope.
func TestStoredIdentityCarriesTheSecretRefCaller(t *testing.T) {
	for name, tt := range map[string]struct {
		identity middleware.AdminIdentity
		query    string
		want     appsecretstore.Caller
	}{
		"console user": {
			identity: middleware.AdminIdentity{Kind: middleware.AdminIdentityHuman, Email: "a@example.com"},
			query:    "?allow_unverified_secret_refs=true",
			want:     appsecretstore.Caller{MayReference: true, AllowUnverified: true, Actor: "a@example.com"},
		},
		"service credential without the scope": {
			identity: middleware.AdminIdentity{Kind: middleware.AdminIdentityService, Subject: "svc", Scopes: []string{"consumers:write"}},
			want:     appsecretstore.Caller{Actor: "svc"},
		},
		"service credential with the scope": {
			identity: middleware.AdminIdentity{Kind: middleware.AdminIdentityService, Subject: "svc", Scopes: []string{middleware.ScopeSecretStoresRead}},
			want:     appsecretstore.Caller{MayReference: true, Actor: "svc"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			app := fiber.New()
			var got appsecretstore.Caller
			app.Post("/v1/gateways/:id/consumers", func(c *fiber.Ctx) error {
				middleware.StoreAdminIdentity(c, tt.identity)
				got = appsecretstore.CallerFrom(c.UserContext())
				return c.SendStatus(fiber.StatusNoContent)
			})
			_, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/v1/gateways/g/consumers"+tt.query, nil))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
