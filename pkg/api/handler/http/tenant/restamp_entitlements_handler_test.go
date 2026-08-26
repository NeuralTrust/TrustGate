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

package tenant_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tenanthttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/tenant"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/gateway/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const fullStamp = `{"entitlements":{"tier":"standard","burst_per_min":300,"quota_per_month":100000,"max_instances":5,"retention_days":30}}`

// callerTenant is what a tenant-scoped admin JWT puts on the request. Platform
// tokens carry no tenant, which is what this endpoint requires.
func newApp(t *testing.T, callerTenant string) (*fiber.App, *mocks.EntitlementsRestamper) {
	t.Helper()
	restamper := mocks.NewEntitlementsRestamper(t)
	h := tenanthttp.NewRestampEntitlementsHandler(restamper)

	a := fiber.New()
	a.Use(func(c *fiber.Ctx) error {
		if callerTenant != "" {
			c.Locals(string(infracontext.TenantIDContextKey), callerTenant)
		}
		return c.Next()
	})
	a.Put("/api/v1/tenants/:tenant_id/entitlements", h.Handle)
	return a, restamper
}

func put(t *testing.T, a *fiber.App, path, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.Test(req)
	require.NoError(t, err)
	return resp
}

func TestRestampAppliesTheStampAcrossTheTenant(t *testing.T) {
	a, restamper := newApp(t, "")
	restamper.EXPECT().
		RestampTenant(mock.Anything, "acme", mock.MatchedBy(func(e domain.Entitlements) bool {
			return e.Tier == "standard" && e.RetentionDays != nil && *e.RetentionDays == 30
		})).
		Return(appgateway.RestampResult{Stamped: 3, MaxInstances: 5}, nil).Once()

	resp := put(t, a, "/api/v1/tenants/acme/entitlements", fullStamp)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got tenanthttp.RestampEntitlementsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.Equal(t, "acme", got.TenantID)
	require.Equal(t, 3, got.Stamped)
	require.False(t, got.OverCap)
}

// A downgrade past the cap is reported, not refused: refusing would leave every
// gateway of the tenant on the old plan.
func TestRestampReportsOverCapWithoutFailing(t *testing.T) {
	a, restamper := newApp(t, "")
	restamper.EXPECT().
		RestampTenant(mock.Anything, "acme", mock.Anything).
		Return(appgateway.RestampResult{Stamped: 4, MaxInstances: 1, OverCap: true}, nil).Once()

	resp := put(t, a, "/api/v1/tenants/acme/entitlements",
		`{"entitlements":{"tier":"free","burst_per_min":60,"quota_per_month":10000,"max_instances":1,"retention_days":7}}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got tenanthttp.RestampEntitlementsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.True(t, got.OverCap)
	require.Equal(t, 4, got.Stamped)
}

// Stamping crosses tenants by nature, so a tenant-scoped token must never reach it
// — not even to re-stamp its own tenant.
func TestRestampRejectsTenantScopedTokens(t *testing.T) {
	a, _ := newApp(t, "acme")

	resp := put(t, a, "/api/v1/tenants/acme/entitlements", fullStamp)
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
}

func TestRestampRejectsMissingEntitlements(t *testing.T) {
	a, _ := newApp(t, "")

	resp := put(t, a, "/api/v1/tenants/acme/entitlements", `{}`)
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
}

// 0 is the unlimited sentinel the whole contract uses, so it must be accepted here
// too rather than read as a missing value.
func TestRestampAcceptsUnlimitedRetention(t *testing.T) {
	a, restamper := newApp(t, "")
	restamper.EXPECT().
		RestampTenant(mock.Anything, "acme", mock.MatchedBy(func(e domain.Entitlements) bool {
			return e.RetentionDays != nil && *e.RetentionDays == 0
		})).
		Return(appgateway.RestampResult{Stamped: 1}, nil).Once()

	resp := put(t, a, "/api/v1/tenants/acme/entitlements",
		`{"entitlements":{"tier":"enterprise","burst_per_min":1000,"quota_per_month":0,"max_instances":0,"retention_days":0}}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}
