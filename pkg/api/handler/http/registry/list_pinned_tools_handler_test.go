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
	"time"

	registryhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	appmocks "github.com/NeuralTrust/TrustGate/pkg/app/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func listPinnedToolsApp(svc appregistry.PinnedToolService) *fiber.App {
	app := fiber.New()
	app.Get("/v1/gateways/:gateway_id/registries/:id/pinned-tools", registryhttp.NewListPinnedToolsHandler(svc).Handle)
	return app
}

func TestListPinnedToolsHandler_ShapesPendingWithApprovedVersion(t *testing.T) {
	gw, reg := ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]()
	decided := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	svc := appmocks.NewPinnedToolService(t)
	pending := domain.ToolStatusPending
	svc.EXPECT().List(mock.Anything, gw, reg, &pending).Return(&appregistry.PinnedToolList{
		ToolPolicy: domain.ToolPolicyPinned,
		Items: []appregistry.PinnedToolView{{
			PinnedTool: domain.PinnedTool{Name: "search", Fingerprint: "v2", Status: domain.ToolStatusPending, Definition: []byte(`{"name":"search","description":"new"}`)},
			Approved:   &domain.PinnedTool{Name: "search", Fingerprint: "v1", Status: domain.ToolStatusApproved, Definition: []byte(`{"name":"search","description":"old"}`), DecidedAt: decided, DecidedBy: "ana@acme.io"},
		}},
	}, nil)

	resp, err := listPinnedToolsApp(svc).Test(httptest.NewRequest(http.MethodGet,
		"/v1/gateways/"+gw.String()+"/registries/"+reg.String()+"/pinned-tools?status=pending", nil))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	raw, _ := io.ReadAll(resp.Body)
	var body struct {
		ToolPolicy string `json:"tool_policy"`
		Total      int    `json:"total"`
		Items      []struct {
			Name            string          `json:"name"`
			Fingerprint     string          `json:"fingerprint"`
			Status          string          `json:"status"`
			Definition      json.RawMessage `json:"definition"`
			DecidedAt       *time.Time      `json:"decided_at"`
			ApprovedVersion *struct {
				Fingerprint string          `json:"fingerprint"`
				Definition  json.RawMessage `json:"definition"`
				DecidedBy   string          `json:"decided_by"`
			} `json:"approved_version"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(raw, &body), string(raw))
	assert.Equal(t, "pinned", body.ToolPolicy)
	assert.Equal(t, 1, body.Total)
	require.Len(t, body.Items, 1)
	it := body.Items[0]
	assert.Equal(t, "v2", it.Fingerprint)
	assert.Nil(t, it.DecidedAt, "a pending row has no decision time")
	require.NotNil(t, it.ApprovedVersion)
	assert.Equal(t, "v1", it.ApprovedVersion.Fingerprint)
	assert.JSONEq(t, `{"name":"search","description":"old"}`, string(it.ApprovedVersion.Definition))
	assert.Equal(t, "ana@acme.io", it.ApprovedVersion.DecidedBy)
}

func TestListPinnedToolsHandler_RejectsAnUnknownStatus(t *testing.T) {
	svc := appmocks.NewPinnedToolService(t) // must not be called
	resp, err := listPinnedToolsApp(svc).Test(httptest.NewRequest(http.MethodGet,
		"/v1/gateways/"+ids.New[ids.GatewayKind]().String()+"/registries/"+ids.New[ids.RegistryKind]().String()+"/pinned-tools?status=bogus", nil))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestListPinnedToolsHandler_EmptyListIsAnArrayNotNull(t *testing.T) {
	gw, reg := ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]()
	svc := appmocks.NewPinnedToolService(t)
	svc.EXPECT().List(mock.Anything, gw, reg, (*domain.ToolStatus)(nil)).Return(&appregistry.PinnedToolList{ToolPolicy: domain.ToolPolicyAuto}, nil)
	resp, err := listPinnedToolsApp(svc).Test(httptest.NewRequest(http.MethodGet,
		"/v1/gateways/"+gw.String()+"/registries/"+reg.String()+"/pinned-tools", nil))
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(raw), `"items":[]`)
}
