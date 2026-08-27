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

package http_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	apihandler "github.com/NeuralTrust/TrustGate/pkg/api/handler/http"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func TestOpenAPIHandlerServesOpenAPI3Document(t *testing.T) {
	t.Parallel()
	app := fiber.New()
	app.Get("/docs/openapi.json", apihandler.NewOpenAPIHandler().Handle)

	res, err := app.Test(httptest.NewRequest(http.MethodGet, "/docs/openapi.json", nil))
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, fiber.StatusOK, res.StatusCode)
	require.Equal(t, fiber.MIMEApplicationJSON, res.Header.Get(fiber.HeaderContentType))

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	var document struct {
		OpenAPI string `json:"openapi"`
		Info    struct {
			Title string `json:"title"`
		} `json:"info"`
		Servers []struct {
			URL string `json:"url"`
		} `json:"servers"`
		Paths map[string]json.RawMessage `json:"paths"`
	}
	require.NoError(t, json.Unmarshal(body, &document))
	require.Equal(t, "3.0.0", document.OpenAPI)
	require.Equal(t, "TrustGate Admin API", document.Info.Title)
	require.Contains(t, document.Paths, "/v1/gateways")
	// A relative server keeps the base URL anchored to the host serving the spec.
	require.Len(t, document.Servers, 1)
	require.Equal(t, "/", document.Servers[0].URL)
}
