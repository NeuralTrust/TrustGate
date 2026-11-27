//go:build functional

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

package functional_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// The models catalog narrowed by a registry asks the provider with that
// registry's credentials, so only the tenant that owns the gateway may name it.
func TestModelsCatalog_RegistryNarrowingIsTenantScoped(t *testing.T) {
	var listings atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/models") {
			listings.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt-4o","object":"model"}]}`))
	}))
	t.Cleanup(upstream.Close)

	owner := uniqueName("tenant-owner")
	gatewayID := CreateGateway(t, map[string]any{"name": uniqueName("catalog-scope"), "tenant_id": owner})
	registry := validRegistryPayload(uniqueName("catalog-scope-openai"))
	registry["provider_options"] = map[string]any{"base_url": upstream.URL + "/v1"}
	registryID := CreateRegistry(t, gatewayID, registry)

	url := fmt.Sprintf("%s/v1/models-catalog?provider=openai&gateway_id=%s&registry_id=%s", AdminURL, gatewayID, registryID)
	as := func(tenant string) map[string]string {
		return map[string]string{"Authorization": "Bearer " + userToken(t, tenant, uniqueName("user"))}
	}

	status, body := sendRequest(t, http.MethodGet, url, as(uniqueName("tenant-other")), nil)
	require.Equal(t, http.StatusNotFound, status, "a foreign tenant must not narrow by this registry: %v", body)
	require.Zero(t, listings.Load(), "a refused request must not reach the registry's provider")

	status, body = sendRequest(t, http.MethodGet, url, as(owner), nil)
	require.Equal(t, http.StatusOK, status, "the owner narrows by its own registry: %v", body)
	require.Positive(t, listings.Load(), "the owner's request lists the registry's models")

	status, _ = sendRequest(t, http.MethodGet, AdminURL+"/v1/models-catalog?provider=openai", as(uniqueName("tenant-other")), nil)
	require.Equal(t, http.StatusOK, status, "the unscoped catalog stays open to every tenant")
}
