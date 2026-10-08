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
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDBLessDataPlane_CanonicalSmartRoutingAndLKGRecovery(t *testing.T) {
	defer Track(t, "DBLessDataPlane")()

	const lowModel, highModel = "dbless-low-model", "dbless-high-model"
	low := newJSONUpstream(t, "dbless-smart-low")
	high := newJSONUpstream(t, "dbless-smart-high")
	apiKey, path := setupSmartRoute(t, low, high, lowModel, highModel)

	require.True(t, pollDBLessReady(AdminURL, 30*time.Second),
		"admin must become ready after a fresh canonical compile")
	status, ready := sendRequest(t, http.MethodGet, AdminURL+"/readyz", nil, nil)
	require.Equal(t, http.StatusOK, status)
	dependencies, ok := ready["dependencies"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "ok", dependencies["compiled_snapshot"])

	lkgPath := filepath.Join(t.TempDir(), "smart-routing.lkg")
	overrides := func(port int, token string) []string {
		return append(dblessOverrides(lkgPath, token, uniqueName("dbless-smart"), port),
			"FIREWALL_BASE_URL="+FirewallComplexityStub.URL(),
			"FIREWALL_SECRET_KEY="+firewallComplexityFunctionalSecret,
			"FIREWALL_COMPLEXITY_MODEL_REVISION=9619f81d9db28141fc1cc0a3833c8446260ce603")
	}
	port := GlobalConfig.Server.ProxyPort + 103
	base, _ := startDBLessProxyPlane(t, port, overrides(port, dblessConfigSyncToken))
	require.True(t, pollDBLessReady(base, 30*time.Second),
		"DB-less proxy must become ready after admitting a canonical live snapshot")
	require.True(t, pollProxyStatusAt(t, base, apiKey, path,
		smartChatRequest(smartRouteLowContent), http.StatusOK, 30*time.Second),
		"canonical smart consumer must arrive through config sync")
	status, ready = sendRequest(t, http.MethodGet, base+"/readyz", nil, nil)
	require.Equal(t, http.StatusOK, status)
	dependencies, ok = ready["dependencies"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "ok", dependencies["snapshot"])

	assertRoutes := func(base string) {
		for _, tc := range []struct {
			content, marker, model string
			upstream               *fakeUpstream
		}{
			{smartRouteLowContent, "dbless-smart-low", lowModel, low},
			{smartRouteHighContent, "dbless-smart-high", highModel, high},
		} {
			status, _, body := proxyPostAt(t, base, apiKey, path, smartChatRequest(tc.content))
			require.Equal(t, http.StatusOK, status, "body: %s", body)
			assert.Contains(t, string(body), tc.marker)
			assert.Contains(t, string(tc.upstream.LastBody()), tc.model)
		}
	}
	assertRoutes(base)

	require.Eventually(t, func() bool {
		info, err := os.Stat(lkgPath)
		return err == nil && info.Size() > 0
	}, 5*time.Second, 25*time.Millisecond, "canonical snapshot must be persisted")
	ciphertext, err := os.ReadFile(lkgPath)
	require.NoError(t, err)
	assert.False(t, bytes.Contains(ciphertext, []byte(lowModel)), "LKG must not contain plaintext routing JSON")

	port++
	restored, _ := startDBLessProxyPlane(t, port, overrides(port, "wrong-config-sync-token"))
	require.True(t, pollDBLessReady(restored, 30*time.Second),
		"a new DB-less proxy must recover canonical encrypted LKG without live sync")
	status, ready = sendRequest(t, http.MethodGet, restored+"/readyz", nil, nil)
	require.Equal(t, http.StatusOK, status)
	dependencies, ok = ready["dependencies"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "ok", dependencies["snapshot"])
	assertRoutes(restored)
}
