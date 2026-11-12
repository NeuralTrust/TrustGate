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

package store_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	storehttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store"
	"github.com/NeuralTrust/TrustGate/pkg/domain/dataplane"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeLLMAvailability struct {
	got dataplane.StoreAvailability
	ids []ids.GatewayID
}

func (f *fakeLLMAvailability) LLMAvailability(_ context.Context, gatewayID ids.GatewayID) (dataplane.StoreAvailability, error) {
	f.ids = append(f.ids, gatewayID)
	return f.got, nil
}

func TestLLMAvailabilityHandler_Get(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	svc := &fakeLLMAvailability{got: dataplane.StoreAvailability{Reason: dataplane.StoreDataPlaneOutdated, MinVersion: "v0.83.0", LowestVersion: "v0.80.0"}}
	app := fiber.New()
	app.Get("/v1/gateways/:gateway_id/store/llm-availability", storehttp.NewLLMAvailabilityHandler(svc).Get)

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/v1/gateways/"+gw.String()+"/store/llm-availability", nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	assert.JSONEq(t, `{"available":false,"reason":"data_plane_outdated","min_version":"v0.83.0","lowest_version":"v0.80.0"}`, string(body))
	assert.Equal(t, []ids.GatewayID{gw}, svc.ids)
}
