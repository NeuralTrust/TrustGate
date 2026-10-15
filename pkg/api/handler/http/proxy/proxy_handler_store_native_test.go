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

package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apiresolver "github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The store never serves a native Bedrock route. The resolver does not parse one
// under the store slug, and the store handler refuses one that reaches it anyway
// instead of selecting a consumer and relaying it: the mock forwarder has no
// expectation, so any call to it fails the test.
func TestHandleStore_RefusesANativeBedrockRoute(t *testing.T) {
	gatewayID, authID := ids.New[ids.GatewayKind](), ids.New[ids.AuthKind]()
	data := storeData(gatewayID, authID, personalSpec{provider: "bedrock", allowed: []string{"*"}})
	slipped := func(c *fiber.Ctx) error {
		c.Locals(apiresolver.ProxyRouteLocalsKey, apiresolver.ProxyRoute{
			ConsumerSlug: "store",
			SourceFormat: adapter.FormatBedrock,
			Capability:   apiresolver.CapabilityBedrockNative,
			Rest:         "/model/amazon.nova-lite-v1:0/converse",
			Bedrock: &adapter.BedrockNativeRoute{
				Op: adapter.BedrockOpConverse, RawModelID: "amazon.nova-lite-v1:0", ModelID: "amazon.nova-lite-v1:0",
			},
		})
		return c.Next()
	}
	app, _, _ := newStoreApp(t, data, ownerAuth(gatewayID, authID), nil, slipped)
	req := httptest.NewRequest(http.MethodPost, "/store/model/amazon.nova-lite-v1:0/converse",
		strings.NewReader(`{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`))
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusNotFound, resp.StatusCode)
}
