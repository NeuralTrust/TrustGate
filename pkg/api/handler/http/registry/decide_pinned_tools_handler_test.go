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

package registry_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	registryhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	appmocks "github.com/NeuralTrust/TrustGate/pkg/app/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func decidePinnedToolsApp(svc appregistry.PinnedToolService, actor string) *fiber.App {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		if actor != "" {
			c.Locals(string(infracontext.UserEmailContextKey), actor)
		}
		return c.Next()
	})
	app.Post("/v1/gateways/:gateway_id/registries/:id/pinned-tools/decisions", registryhttp.NewDecidePinnedToolsHandler(svc).Handle)
	return app
}

func postDecisions(t *testing.T, app *fiber.App, gw ids.GatewayID, reg ids.RegistryID, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/gateways/"+gw.String()+"/registries/"+reg.String()+"/pinned-tools/decisions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestDecidePinnedToolsHandler_AppliesWithTheAuthenticatedActor(t *testing.T) {
	gw, reg := ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]()
	svc := appmocks.NewPinnedToolService(t)
	svc.EXPECT().Decide(mock.Anything, appregistry.DecideToolsInput{
		GatewayID: gw, RegistryID: reg,
		Approve:   []domain.ToolRef{{Name: "a", Fingerprint: "f1"}},
		Reject:    []domain.ToolRef{{Name: "b", Fingerprint: "f2"}},
		DecidedBy: "ana@acme.io",
	}).Return(nil)

	// A decided_by smuggled in the body is ignored: the actor is the principal.
	resp := postDecisions(t, decidePinnedToolsApp(svc, "ana@acme.io"), gw, reg,
		`{"approve":[{"name":"a","fingerprint":"f1"}],"reject":[{"name":"b","fingerprint":"f2"}],"decided_by":"mallory"}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestDecidePinnedToolsHandler_BadBodiesAre400(t *testing.T) {
	cases := map[string]string{
		"same ref in both lists": `{"approve":[{"name":"a","fingerprint":"f"}],"reject":[{"name":"a","fingerprint":"f"}]}`,
		"empty":                  `{}`,
		"missing fingerprint":    `{"approve":[{"name":"a"}]}`,
		"not json":               `nope`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			svc := appmocks.NewPinnedToolService(t) // must not be called
			resp := postDecisions(t, decidePinnedToolsApp(svc, "ana"), ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind](), body)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

func TestDecidePinnedToolsHandler_SameNameDifferentFingerprintIsNotAConflict(t *testing.T) {
	gw, reg := ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]()
	svc := appmocks.NewPinnedToolService(t)
	svc.EXPECT().Decide(mock.Anything, mock.Anything).Return(nil)
	resp := postDecisions(t, decidePinnedToolsApp(svc, "ana"), gw, reg,
		`{"approve":[{"name":"a","fingerprint":"new"}],"reject":[{"name":"a","fingerprint":"old"}]}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestDecidePinnedToolsHandler_UnknownRefIs422(t *testing.T) {
	gw, reg := ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]()
	svc := appmocks.NewPinnedToolService(t)
	svc.EXPECT().Decide(mock.Anything, mock.Anything).Return(domain.ErrUnknownToolRefs)
	resp := postDecisions(t, decidePinnedToolsApp(svc, "ana"), gw, reg, `{"approve":[{"name":"ghost","fingerprint":"f"}]}`)
	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
}

func TestDecidePinnedToolsHandler_ForeignRegistryIs404(t *testing.T) {
	gw, reg := ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]()
	svc := appmocks.NewPinnedToolService(t)
	svc.EXPECT().Decide(mock.Anything, mock.Anything).Return(domain.ErrNotFound)
	resp := postDecisions(t, decidePinnedToolsApp(svc, "ana"), gw, reg, `{"reject":[{"name":"a","fingerprint":"f"}]}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// Without a resolvable admin identity the decision would be stored with a NULL
// decided_by: both mutating routes must refuse it before touching anything.
func TestPinnedToolRoutes_WithoutAnActorAre401(t *testing.T) {
	gw, reg := ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]()
	svc := appmocks.NewPinnedToolService(t) // must not be called

	resp := postDecisions(t, decidePinnedToolsApp(svc, ""), gw, reg, `{"approve":[{"name":"a","fingerprint":"f"}]}`)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "decisions")

	app := fiber.New()
	app.Put("/v1/gateways/:gateway_id/registries/:id/tool-pinning", registryhttp.NewEnableToolPinningHandler(svc, &stubIntrospector{}).Handle)
	req := httptest.NewRequest(http.MethodPut,
		"/v1/gateways/"+gw.String()+"/registries/"+reg.String()+"/tool-pinning", strings.NewReader(`{"tools":[]}`))
	req.Header.Set("Content-Type", "application/json")
	r, err := app.Test(req)
	require.NoError(t, err)
	defer r.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, r.StatusCode, "tool-pinning")
}
