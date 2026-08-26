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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	registryhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry"
	appopenapi "github.com/NeuralTrust/TrustGate/pkg/app/openapi"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

type validatorFunc func(context.Context, appopenapi.Source) appregistry.OpenAPIValidationResult

func (f validatorFunc) Validate(ctx context.Context, source appopenapi.Source) appregistry.OpenAPIValidationResult {
	return f(ctx, source)
}

func TestValidateOpenAPIHandlerReturnsToolPreview(t *testing.T) {
	t.Parallel()
	validator := validatorFunc(func(_ context.Context, source appopenapi.Source) appregistry.OpenAPIValidationResult {
		require.Equal(t, "https://example.com/openapi.json", source.SpecURL)
		return appregistry.OpenAPIValidationResult{
			OK:             true,
			Stage:          appopenapi.StageCompile,
			OpenAPIVersion: "3.1.0",
			Title:          "Example",
			BaseURL:        "https://example.com/v1",
			Tools: []appregistry.OpenAPIToolPreview{{
				Name: "getUser", Method: "GET", Path: "/users/{id}",
			}},
		}
	})
	app := fiber.New()
	handler := registryhttp.NewValidateOpenAPIHandler(validator)
	app.Post("/v1/gateways/:gateway_id/registries/validate-openapi", handler.Handle)
	gatewayID := ids.New[ids.GatewayKind]()
	req := httptest.NewRequest(
		http.MethodPost,
		"/v1/gateways/"+gatewayID.String()+"/registries/validate-openapi",
		bytes.NewBufferString(`{"spec_url":"https://example.com/openapi.json"}`),
	)
	req.Header.Set("Content-Type", "application/json")

	res, err := app.Test(req)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)
	var payload registryhttp.ValidateOpenAPIResponse
	require.NoError(t, json.NewDecoder(res.Body).Decode(&payload))
	require.True(t, payload.OK)
	require.Equal(t, 1, payload.ToolCount)
	require.Equal(t, "getUser", payload.Tools[0].Name)
	require.NotNil(t, payload.Warnings)
}

func TestValidateOpenAPIHandlerRejectsInvalidURL(t *testing.T) {
	t.Parallel()
	app := fiber.New()
	handler := registryhttp.NewValidateOpenAPIHandler(validatorFunc(
		func(context.Context, appopenapi.Source) appregistry.OpenAPIValidationResult {
			t.Fatal("validator should not be called")
			return appregistry.OpenAPIValidationResult{}
		},
	))
	app.Post("/v1/gateways/:gateway_id/registries/validate-openapi", handler.Handle)
	req := httptest.NewRequest(
		http.MethodPost,
		"/v1/gateways/"+ids.New[ids.GatewayKind]().String()+"/registries/validate-openapi",
		bytes.NewBufferString(`{"spec_url":"file:///tmp/openapi.json"}`),
	)
	req.Header.Set("Content-Type", "application/json")

	res, err := app.Test(req)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusUnprocessableEntity, res.StatusCode)
}
