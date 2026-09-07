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

package diagnostics_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"testing"

	diagnosticshttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/diagnostics"
	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infrajwt "github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRegistryFinder struct {
	registry *registrydomain.Registry
	err      error

	gotGateway  ids.GatewayID
	gotRegistry ids.RegistryID
}

func (f *fakeRegistryFinder) FindByID(
	_ context.Context,
	gatewayID ids.GatewayID,
	id ids.RegistryID,
) (*registrydomain.Registry, error) {
	f.gotGateway, f.gotRegistry = gatewayID, id
	if f.err != nil {
		return nil, f.err
	}
	return f.registry, nil
}

func (f *fakeRegistryFinder) List(
	context.Context,
	registrydomain.ListFilter,
) ([]*registrydomain.Registry, int, error) {
	return nil, 0, nil
}

type fakeCatalogService struct {
	models      []catalogdomain.Model
	err         error
	gotProvider string
}

func (f *fakeCatalogService) ListProviders(context.Context) ([]catalogdomain.Provider, error) {
	return nil, nil
}

func (f *fakeCatalogService) ListModels(_ context.Context, providerCode string) ([]catalogdomain.Model, error) {
	f.gotProvider = providerCode
	if f.err != nil {
		return nil, f.err
	}
	return f.models, nil
}

// fakeAvailability records what it was asked to narrow and returns a fixed
// answer, so the handler's own wiring is what the test observes.
type fakeAvailability struct {
	kept []catalogdomain.Model
	got  appcatalog.ServerlessFilterInput
}

func (f *fakeAvailability) Narrow(
	_ context.Context,
	in appcatalog.ServerlessFilterInput,
) []catalogdomain.Model {
	f.got = in
	return f.kept
}

func llmRegistry(gatewayID ids.GatewayID, id ids.RegistryID, provider string) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:        id,
		GatewayID: gatewayID,
		Name:      "primary",
		Type:      registrydomain.TypeLLM,
		Enabled:   true,
		LLMTarget: &registrydomain.LLMTarget{Provider: provider},
	}
}

func newModelsApp(
	verifier infrajwt.ProxyTokenVerifier,
	finder *fakeRegistryFinder,
	service *fakeCatalogService,
	availability *fakeAvailability,
) *fiber.App {
	app := fiber.New()
	h := diagnosticshttp.NewListRegistryModelsHandler(verifier, finder, service, availability)
	app.Get("/__diagnostics/gateways/:gateway_id/registries/:registry_id/models", h.Handle)
	return app
}

func getModels(t *testing.T, app *fiber.App, gatewayID, registryID, token string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(fiber.MethodGet,
		"/__diagnostics/gateways/"+gatewayID+"/registries/"+registryID+"/models", nil)
	if token != "" {
		req.Header.Set(diagnosticshttp.HeaderDiagnosticsToken, token)
	}
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, raw
}

func modelSlugs(t *testing.T, raw []byte) []string {
	t.Helper()
	var out struct {
		Items []struct {
			Slug string `json:"slug"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(raw, &out))
	slugs := make([]string, 0, len(out.Items))
	for _, item := range out.Items {
		slugs = append(slugs, item.Slug)
	}
	return slugs
}

func TestDiagnosticsRegistryModels_NarrowsCatalogForTheRegistrysProvider(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	finder := &fakeRegistryFinder{registry: llmRegistry(gatewayID, registryID, "openai")}
	service := &fakeCatalogService{models: []catalogdomain.Model{
		{Slug: "gpt-4o", Enabled: true},
		{Slug: "o3", Enabled: true},
	}}
	availability := &fakeAvailability{kept: []catalogdomain.Model{{Slug: "gpt-4o", Enabled: true}}}
	app := newModelsApp(fakeVerifier{claims: diagClaims(gatewayID.String())}, finder, service, availability)

	status, raw := getModels(t, app, gatewayID.String(), registryID.String(), "a.diag.token")

	require.Equal(t, fiber.StatusOK, status, "body: %s", raw)
	assert.Equal(t, []string{"gpt-4o"}, modelSlugs(t, raw))
	// The provider comes from the registry, never from the caller.
	assert.Equal(t, "openai", service.gotProvider)
	assert.Equal(t, "openai", availability.got.ProviderCode)
	assert.Equal(t, gatewayID, availability.got.GatewayID)
	assert.Equal(t, registryID, availability.got.RegistryID)
	assert.Len(t, availability.got.Models, 2, "the narrower receives the full catalog")
	assert.Equal(t, gatewayID, finder.gotGateway)
	assert.Equal(t, registryID, finder.gotRegistry)
}

func TestDiagnosticsRegistryModels_EmptyNarrowingIsReportedAsEmpty(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	app := newModelsApp(
		fakeVerifier{claims: diagClaims(gatewayID.String())},
		&fakeRegistryFinder{registry: llmRegistry(gatewayID, registryID, "openai")},
		&fakeCatalogService{models: []catalogdomain.Model{{Slug: "gpt-4o", Enabled: true}}},
		&fakeAvailability{kept: nil},
	)

	status, raw := getModels(t, app, gatewayID.String(), registryID.String(), "a.diag.token")

	require.Equal(t, fiber.StatusOK, status, "body: %s", raw)
	assert.Empty(t, modelSlugs(t, raw))
	assert.Contains(t, string(raw), `"items":[]`, "items must serialize as an array, never null")
}

func TestDiagnosticsRegistryModels_MissingTokenRejected(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	finder := &fakeRegistryFinder{registry: llmRegistry(gatewayID, registryID, "openai")}
	app := newModelsApp(
		fakeVerifier{claims: diagClaims(gatewayID.String())},
		finder, &fakeCatalogService{}, &fakeAvailability{},
	)

	status, _ := getModels(t, app, gatewayID.String(), registryID.String(), "")

	assert.Equal(t, fiber.StatusUnauthorized, status)
	assert.True(t, finder.gotGateway.IsNil(), "an unauthorized probe must not reach the registry")
}

func TestDiagnosticsRegistryModels_InvalidTokenRejected(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	app := newModelsApp(
		fakeVerifier{err: errors.New("bad signature")},
		&fakeRegistryFinder{registry: llmRegistry(gatewayID, registryID, "openai")},
		&fakeCatalogService{}, &fakeAvailability{},
	)

	status, _ := getModels(t, app, gatewayID.String(), registryID.String(), "a.diag.token")
	assert.Equal(t, fiber.StatusUnauthorized, status)
}

func TestDiagnosticsRegistryModels_WrongPurposeRejected(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	app := newModelsApp(
		fakeVerifier{claims: &infrajwt.Claims{Purpose: "playground", GatewayID: gatewayID.String()}},
		&fakeRegistryFinder{registry: llmRegistry(gatewayID, registryID, "openai")},
		&fakeCatalogService{}, &fakeAvailability{},
	)

	status, _ := getModels(t, app, gatewayID.String(), registryID.String(), "a.playground.token")
	assert.Equal(t, fiber.StatusUnauthorized, status)
}

func TestDiagnosticsRegistryModels_TokenForAnotherGatewayRejected(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	app := newModelsApp(
		fakeVerifier{claims: diagClaims(ids.New[ids.GatewayKind]().String())},
		&fakeRegistryFinder{registry: llmRegistry(gatewayID, registryID, "openai")},
		&fakeCatalogService{}, &fakeAvailability{},
	)

	status, _ := getModels(t, app, gatewayID.String(), registryID.String(), "a.diag.token")
	assert.Equal(t, fiber.StatusUnauthorized, status)
}

func TestDiagnosticsRegistryModels_UnsyncedRegistryIsNotFound(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	app := newModelsApp(
		fakeVerifier{claims: diagClaims(gatewayID.String())},
		&fakeRegistryFinder{err: commonerrors.ErrNotFound},
		&fakeCatalogService{}, &fakeAvailability{},
	)

	status, raw := getModels(t, app, gatewayID.String(), registryID.String(), "a.diag.token")

	// The caller falls back to the unnarrowed catalog on 404, so the status
	// must stay distinguishable from a rejected token. The reason only reaches
	// the server log; the body carries the stable code, as everywhere else.
	assert.Equal(t, fiber.StatusNotFound, status)
	assert.Contains(t, string(raw), "not_found", "body: %s", raw)
}

func TestDiagnosticsRegistryModels_MalformedRegistryIDRejected(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	app := newModelsApp(
		fakeVerifier{claims: diagClaims(gatewayID.String())},
		&fakeRegistryFinder{}, &fakeCatalogService{}, &fakeAvailability{},
	)

	status, _ := getModels(t, app, gatewayID.String(), "not-a-uuid", "a.diag.token")
	assert.Equal(t, fiber.StatusBadRequest, status)
}
