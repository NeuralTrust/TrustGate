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
	"strconv"
	"strings"
	"testing"

	registryhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	registrymocks "github.com/NeuralTrust/TrustGate/pkg/app/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const labelARN = "arn:aws:bedrock:eu-west-1:123456789012:application-inference-profile/abc123"

func labelledRegistry(t *testing.T, gatewayID ids.GatewayID, labels map[string]string) *domain.Registry {
	t.Helper()
	b, err := domain.NewLLMRegistry(gatewayID, "bedrock", "", &domain.LLMTarget{
		Provider:    "bedrock",
		Auth:        domain.NewAPIKeyAuth("sk-test"),
		ModelLabels: labels,
	})
	require.NoError(t, err)
	return b
}

func doJSON(t *testing.T, app *fiber.App, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	out := map[string]any{}
	require.NoError(t, json.Unmarshal(raw, &out), string(raw))
	return resp.StatusCode, out
}

func TestUpdateRegistryHandler_ModelLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		wantSet    bool
		wantLabels map[string]string
	}{
		{
			name:    "absent keeps the stored map",
			body:    `{"name":"renamed"}`,
			wantSet: false,
		},
		{
			name:       "empty object clears the map",
			body:       `{"model_labels":{}}`,
			wantSet:    true,
			wantLabels: map[string]string{},
		},
		{
			name:       "present object replaces the map",
			body:       `{"model_labels":{"` + labelARN + `":"Claude Sonnet (prod)"}}`,
			wantSet:    true,
			wantLabels: map[string]string{labelARN: "Claude Sonnet (prod)"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gatewayID := ids.New[ids.GatewayKind]()
			stored := labelledRegistry(t, gatewayID, map[string]string{labelARN: "Stored"})
			updater := registrymocks.NewUpdater(t)
			updater.EXPECT().
				Update(mock.Anything, mock.MatchedBy(func(in appregistry.UpdateInput) bool {
					if in.SetModelLabels != tt.wantSet {
						return false
					}
					if !tt.wantSet {
						return in.ModelLabels == nil
					}
					return assert.ObjectsAreEqual(tt.wantLabels, in.ModelLabels)
				})).
				Return(stored, nil).
				Once()
			app := fiber.New()
			app.Put("/v1/gateways/:gateway_id/registries/:id", registryhttp.NewUpdateRegistryHandler(updater).Handle)

			status, body := doJSON(t, app, http.MethodPut, "/v1/gateways/"+gatewayID.String()+"/registries/"+stored.ID.String(), tt.body)

			require.Equal(t, http.StatusOK, status, body)
			assert.Equal(t, map[string]any{labelARN: "Stored"}, body["model_labels"])
		})
	}
}

func TestRegistryHandlers_RejectInvalidModelLabels(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"empty value":    `{"model_labels":{"gpt-4o":"  "}}`,
		"empty key":      `{"model_labels":{" ":"GPT-4o"}}`,
		"value too long": `{"model_labels":{"gpt-4o":"` + strings.Repeat("x", 129) + `"}}`,
		"key too long":   `{"model_labels":{"` + strings.Repeat("k", 2049) + `":"GPT-4o"}}`,
		"too many":       `{"model_labels":{` + manyLabels(201) + `}}`,
	}
	for name, labels := range tests {
		t.Run("update "+name, func(t *testing.T) {
			t.Parallel()
			app := fiber.New()
			app.Put("/v1/gateways/:gateway_id/registries/:id", registryhttp.NewUpdateRegistryHandler(registrymocks.NewUpdater(t)).Handle)

			status, body := doJSON(t, app, http.MethodPut,
				"/v1/gateways/"+ids.New[ids.GatewayKind]().String()+"/registries/"+ids.New[ids.RegistryKind]().String(), labels)

			assert.Equal(t, http.StatusUnprocessableEntity, status)
			assert.Equal(t, "validation_failed", body["error"])
		})
		t.Run("create "+name, func(t *testing.T) {
			t.Parallel()
			app := fiber.New()
			app.Post("/v1/gateways/:gateway_id/registries", registryhttp.NewCreateRegistryHandler(registrymocks.NewCreator(t)).Handle)
			payload := `{"name":"bedrock","provider":"bedrock","auth":{"type":"api_key","api_key":{"api_key":"sk-test"}},` + strings.TrimPrefix(labels, "{")

			status, body := doJSON(t, app, http.MethodPost, "/v1/gateways/"+ids.New[ids.GatewayKind]().String()+"/registries", payload)

			assert.Equal(t, http.StatusUnprocessableEntity, status)
			assert.Equal(t, "validation_failed", body["error"])
		})
	}
}

func TestCreateRegistryHandler_PassesModelLabels(t *testing.T) {
	t.Parallel()

	gatewayID := ids.New[ids.GatewayKind]()
	created := labelledRegistry(t, gatewayID, map[string]string{labelARN: "Claude Sonnet (prod)"})
	creator := registrymocks.NewCreator(t)
	creator.EXPECT().
		Create(mock.Anything, mock.MatchedBy(func(in appregistry.CreateInput) bool {
			return in.LLMTarget != nil && in.LLMTarget.ModelLabels[labelARN] == "Claude Sonnet (prod)"
		})).
		Return(created, nil).
		Once()
	app := fiber.New()
	app.Post("/v1/gateways/:gateway_id/registries", registryhttp.NewCreateRegistryHandler(creator).Handle)
	payload := `{"name":"bedrock","provider":"bedrock","auth":{"type":"api_key","api_key":{"api_key":"sk-test"}},"model_labels":{"` + labelARN + `":"Claude Sonnet (prod)"}}`

	status, body := doJSON(t, app, http.MethodPost, "/v1/gateways/"+gatewayID.String()+"/registries", payload)

	require.Equal(t, http.StatusCreated, status, body)
	assert.Equal(t, map[string]any{labelARN: "Claude Sonnet (prod)"}, body["model_labels"])
}

func manyLabels(n int) string {
	parts := make([]string, 0, n)
	for i := range n {
		parts = append(parts, `"model-`+strconv.Itoa(i)+`":"Model"`)
	}
	return strings.Join(parts, ",")
}
