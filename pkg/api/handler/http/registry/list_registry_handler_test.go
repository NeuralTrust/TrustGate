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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	registryhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/response"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	registrymocks "github.com/NeuralTrust/TrustGate/pkg/app/registry/mocks"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestListRegistryHandler_DefaultViewPreservesFlatResponse(t *testing.T) {
	t.Parallel()

	gatewayID := ids.New[ids.GatewayKind]()
	finder := registrymocks.NewFinder(t)
	finder.EXPECT().
		List(mock.Anything, domain.ListFilter{
			GatewayID: gatewayID,
			Page:      1,
			Size:      20,
		}).
		Return([]*domain.Registry{}, 0, nil).
		Once()
	groupedFinder := registrymocks.NewGroupedFinder(t)
	sharedAccounts := registrymocks.NewSharedAccountService(t)
	sharedAccounts.EXPECT().
		Statuses(mock.Anything, gatewayID, []*domain.Registry{}).
		Return(map[ids.RegistryID]*appregistry.SharedAccount{}).
		Once()
	app := newListRegistryApp(registryhttp.NewListRegistryHandler(finder, groupedFinder, sharedAccounts))

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/v1/gateways/"+gatewayID.String()+"/registries", nil))

	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, `{"items":[],"page":1,"size":20,"total":0}`, string(body))
}

func TestListRegistryHandler_FlatViewCarriesSharedAccountStatus(t *testing.T) {
	t.Parallel()

	gatewayID := ids.New[ids.GatewayKind]()
	shared := listMCPRegistry(t, gatewayID, "postman", domain.MCPAccountShared)
	perUser := listMCPRegistry(t, gatewayID, "notion", domain.MCPAccountUser)
	items := []*domain.Registry{shared, perUser}
	finder := registrymocks.NewFinder(t)
	finder.EXPECT().
		List(mock.Anything, domain.ListFilter{GatewayID: gatewayID, Page: 1, Size: 20}).
		Return(items, 2, nil).
		Once()
	sharedAccounts := registrymocks.NewSharedAccountService(t)
	sharedAccounts.EXPECT().
		Statuses(mock.Anything, gatewayID, items).
		Return(map[ids.RegistryID]*appregistry.SharedAccount{
			shared.ID: {Provider: "postman", Connected: true, NeedsReconnect: true},
		}).
		Once()
	app := newListRegistryApp(registryhttp.NewListRegistryHandler(finder, registrymocks.NewGroupedFinder(t), sharedAccounts))

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/v1/gateways/"+gatewayID.String()+"/registries", nil))

	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body response.ListRegistryResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Len(t, body.Items, 2)
	require.NotNil(t, body.Items[0].SharedAccount)
	assert.True(t, body.Items[0].SharedAccount.Connected)
	assert.True(t, body.Items[0].SharedAccount.NeedsReconnect)
	assert.Nil(t, body.Items[1].SharedAccount)
}

func listMCPRegistry(t *testing.T, gatewayID ids.GatewayID, provider string, account domain.MCPAccount) *domain.Registry {
	t.Helper()
	reg, err := domain.NewMCPRegistry(gatewayID, provider, "", &domain.MCPTarget{
		URL:  "https://mcp." + provider + ".example/mcp",
		Code: "com." + provider + "/mcp",
		Auth: &domain.MCPAuth{
			Mode: domain.MCPAuthModeForwarded, Provider: provider, ClientID: "cid",
			AuthorizeURL: "https://" + provider + ".example/a", TokenURL: "https://" + provider + ".example/t",
			Account: account,
		},
	})
	require.NoError(t, err)
	return reg
}

func TestListRegistryHandler_GroupedViewMapsInstancesAndTotals(t *testing.T) {
	t.Parallel()

	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	instance := &domain.Registry{
		ID:        registryID,
		GatewayID: gatewayID,
		Name:      "Primary",
		Type:      domain.TypeLLM,
		LLMTarget: &domain.LLMTarget{
			Provider: "openai",
			Auth: &domain.TargetAuth{
				Type: domain.AuthTypeAPIKey,
				APIKey: &domain.APIKeyAuth{
					APIKey: "secret-value-1234",
				},
			},
		},
	}
	finder := registrymocks.NewFinder(t)
	groupedFinder := registrymocks.NewGroupedFinder(t)
	groupedFinder.EXPECT().
		Find(mock.Anything, gatewayID).
		Return(appregistry.GroupedRegistryResult{
			Groups: []appregistry.RegistryProviderGroup{{
				Provider:  "openai",
				Instances: []*domain.Registry{instance},
			}},
			TotalInstances: 1,
		}, nil).
		Once()
	app := newListRegistryApp(registryhttp.NewListRegistryHandler(finder, groupedFinder, registrymocks.NewSharedAccountService(t)))

	req := httptest.NewRequest(http.MethodGet, "/v1/gateways/"+gatewayID.String()+"/registries?view=grouped&type=LLM", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body response.GroupedRegistryResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "grouped", body.View)
	assert.Equal(t, 1, body.TotalGroups)
	assert.Equal(t, 1, body.TotalInstances)
	require.Len(t, body.Groups, 1)
	assert.Equal(t, "openai", body.Groups[0].Provider)
	assert.Equal(t, "LLM", body.Groups[0].Type)
	assert.Equal(t, 1, body.Groups[0].InstanceCount)
	require.Len(t, body.Groups[0].Instances, 1)
	assert.Equal(t, registryID, body.Groups[0].Instances[0].ID)
	require.NotNil(t, body.Groups[0].Instances[0].Auth)
	require.NotNil(t, body.Groups[0].Instances[0].Auth.APIKey)
	assert.Equal(t, secret.Redacted+"1234", body.Groups[0].Instances[0].Auth.APIKey.APIKey)
}

func TestListRegistryHandler_GroupedViewReturnsEmptyGroupsArray(t *testing.T) {
	t.Parallel()

	gatewayID := ids.New[ids.GatewayKind]()
	finder := registrymocks.NewFinder(t)
	groupedFinder := registrymocks.NewGroupedFinder(t)
	groupedFinder.EXPECT().
		Find(mock.Anything, gatewayID).
		Return(appregistry.GroupedRegistryResult{Groups: []appregistry.RegistryProviderGroup{}}, nil).
		Once()
	app := newListRegistryApp(registryhttp.NewListRegistryHandler(finder, groupedFinder, registrymocks.NewSharedAccountService(t)))

	req := httptest.NewRequest(http.MethodGet, "/v1/gateways/"+gatewayID.String()+"/registries?view=grouped&type=LLM", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, []any{}, body["groups"])
	assert.Equal(t, float64(0), body["total_groups"])
	assert.Equal(t, float64(0), body["total_instances"])
}

func TestListRegistryHandler_InvalidViewQuery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		query string
	}{
		{name: "unknown view", query: "?view=unknown"},
		{name: "type without view", query: "?type=LLM"},
		{name: "empty type without view", query: "?type="},
		{name: "missing type", query: "?view=grouped"},
		{name: "unsupported type", query: "?view=grouped&type=MCP"},
		{name: "name filter", query: "?view=grouped&type=LLM&name="},
		{name: "page", query: "?view=grouped&type=LLM&page=1"},
		{name: "size", query: "?view=grouped&type=LLM&size=20"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			gatewayID := ids.New[ids.GatewayKind]()
			finder := registrymocks.NewFinder(t)
			groupedFinder := registrymocks.NewGroupedFinder(t)
			app := newListRegistryApp(registryhttp.NewListRegistryHandler(finder, groupedFinder, registrymocks.NewSharedAccountService(t)))

			req := httptest.NewRequest(http.MethodGet, "/v1/gateways/"+gatewayID.String()+"/registries"+test.query, nil)
			resp, err := app.Test(req)

			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var body map[string]any
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
			assert.Equal(t, "invalid_query", body["error"])
		})
	}
}

func TestListRegistryHandler_GroupedViewRejectsResultAboveMaximum(t *testing.T) {
	t.Parallel()

	gatewayID := ids.New[ids.GatewayKind]()
	finder := registrymocks.NewFinder(t)
	groupedFinder := registrymocks.NewGroupedFinder(t)
	groupedFinder.EXPECT().
		Find(mock.Anything, gatewayID).
		Return(appregistry.GroupedRegistryResult{}, commonerrors.ErrResultTooLarge).
		Once()
	app := newListRegistryApp(registryhttp.NewListRegistryHandler(finder, groupedFinder, registrymocks.NewSharedAccountService(t)))

	req := httptest.NewRequest(http.MethodGet, "/v1/gateways/"+gatewayID.String()+"/registries?view=grouped&type=LLM", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "result_too_large", body["error"])
}

func newListRegistryApp(handler *registryhttp.ListRegistryHandler) *fiber.App {
	app := fiber.New()
	app.Get("/v1/gateways/:gateway_id/registries", handler.Handle)
	return app
}
