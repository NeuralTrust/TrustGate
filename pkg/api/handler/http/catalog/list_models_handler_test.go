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

package catalog_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	cataloghttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/catalog"
	catalogmocks "github.com/NeuralTrust/TrustGate/pkg/app/catalog/mocks"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func getAzureModelsCatalog(t *testing.T, kept []catalogdomain.Model, narrowErr error) (int, string) {
	t.Helper()
	catalog := []catalogdomain.Model{{Slug: "gpt-5.6-terra", Enabled: true}}
	service := catalogmocks.NewService(t)
	service.EXPECT().ListModels(mock.Anything, "azure").Return(catalog, nil).Once()
	availability := catalogmocks.NewRegistryAvailability(t)
	availability.EXPECT().Narrow(mock.Anything, mock.Anything).Return(kept, narrowErr).Once()
	lister := catalogmocks.NewLiveCatalogLister(t)

	app := fiber.New()
	h := cataloghttp.NewListModelsHandler(service, availability, lister)
	app.Get("/v1/models-catalog", h.Handle)

	target := fmt.Sprintf("/v1/models-catalog?provider=azure&gateway_id=%s&registry_id=%s",
		ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]())
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, target, nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(raw)
}

func TestListModelsHandler_AzureListingFailureIsBadGateway(t *testing.T) {
	status, body := getAzureModelsCatalog(t, nil,
		fmt.Errorf("%w: the azure provider did not list this registry's models", commonerrors.ErrUpstreamUnavailable))

	assert.Equal(t, fiber.StatusBadGateway, status, body)
	assert.Contains(t, body, "upstream_unavailable")
	assert.NotContains(t, body, "gpt-5.6-terra", "a catalog name must not be offered as a deployment")
}

func TestListModelsHandler_AzureRejectedCredentialsAreInvalidConfig(t *testing.T) {
	status, body := getAzureModelsCatalog(t, nil,
		fmt.Errorf("%w: the azure provider rejected this registry's endpoint or credentials", commonerrors.ErrInvalidConfig))

	assert.Equal(t, fiber.StatusUnprocessableEntity, status, body)
	assert.Contains(t, body, "invalid_config")
}

func TestListModelsHandler_AzureListsDeployments(t *testing.T) {
	status, body := getAzureModelsCatalog(t,
		[]catalogdomain.Model{{Slug: "gpt-56-terra", ExternalID: "gpt-56-terra", Enabled: true}}, nil)

	assert.Equal(t, fiber.StatusOK, status, body)
	assert.Contains(t, body, `"slug":"gpt-56-terra"`)
	assert.NotContains(t, body, "gpt-5.6-terra")
}
