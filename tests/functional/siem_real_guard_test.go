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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSIEMRealTrustGuard(t *testing.T) {
	if os.Getenv("FUNCTIONAL_TRUSTGUARD_BASE_URL") == "" {
		t.Skip("requires a real TrustGuard service")
	}
	control := os.Getenv("FUNCTIONAL_TRUSTGUARD_CONTROL_URL")
	token := os.Getenv("FUNCTIONAL_TRUSTGUARD_ADMIN_TOKEN")
	require.NotEmpty(t, control)
	require.NotEmpty(t, token)
	tenantID := getEnv("FUNCTIONAL_SIEM_TENANT_ID", "00000000-0000-0000-0000-000000000001")
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("eng1564-gw"), "tenant_id": tenantID})
	guardCall := func(method, path string, payload any) map[string]any {
		status, body := sendRequest(t, method, control+path, map[string]string{"Authorization": "Bearer " + token}, payload)
		require.Contains(t, []int{http.StatusOK, http.StatusCreated}, status, "guard fixture %s: %v", path, body)
		return body
	}
	guardID := guardCall(http.MethodPost, "/v1/guards", map[string]any{"name": uniqueName("eng1564-guard")})["id"].(string)
	base := "/v1/guards/" + guardID
	collectorID := guardCall(http.MethodPost, base+"/collectors", map[string]any{"name": uniqueName("eng1564-collector")})["id"].(string)
	policyID := guardCall(http.MethodPost, base+"/policies", map[string]any{"name": uniqueName("eng1564-policy")})["id"].(string)
	detectorID := guardCall(http.MethodPost, base+"/detectors", map[string]any{"name": uniqueName("eng1564-code"), "plugin_slug": "code_sanitation", "settings": map[string]any{"mode": "block", "apply_all_languages": true}})["id"].(string)
	for i, direction := range []string{"input", "output"} {
		guardCall(http.MethodPost, base+"/policies/"+policyID+"/execution-rules", map[string]any{"detector_id": detectorID, "action": "block", "direction": direction, "position": i, "enabled": true})
	}
	guardCall(http.MethodPut, base+"/collectors/"+collectorID, map[string]any{"name": "eng1564-collector", "default_policy_id": policyID, "metadata": map[string]string{"gateway_id": gatewayID}})
	up := newJSONUpstream(t, "eng1564-allowed")
	backendID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("eng1564-backend"), up.URL()))
	gatePolicy := policyPlugin("trustguard", map[string]any{"collector_id": collectorID, "direction": "request_response"})
	gatePolicy["name"] = uniqueName("eng1564-policy")
	gatePolicyID := CreatePolicy(t, gatewayID, gatePolicy)
	consumerID := CreateConsumerWithRegistries(t, gatewayID, uniqueName("eng1564-consumer"), backendID)
	AttachPolicy(t, gatewayID, consumerID, gatePolicyID)
	apiKey := createAndAttachAPIKey(t, gatewayID, consumerID)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	authID := CreateAuth(t, gatewayID, map[string]any{"name": uniqueName("eng1564-identity"), "type": "oauth2", "config": map[string]any{"oauth2": map[string]any{
		"issuer": "urn:eng1564:identity", "audiences": []string{"eng1564-gateway"}, "allowed_algorithms": []string{"RS256"},
		"public_keys": []string{string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKey}))},
	}}})
	AttachAuth(t, gatewayID, consumerID, authID)
	identityToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "urn:eng1564:identity", "aud": "eng1564-gateway", "sub": "eng1564-full-user", "email": "full-user@example.test", "exp": time.Now().Add(time.Hour).Unix()}).SignedString(key)
	require.NoError(t, err)
	path := chatCompletionsPath(t, consumerID)
	traces := make(map[int]string)
	requestIDs := make(map[int]string)
	for _, tc := range []struct {
		prompt string
		status int
	}{{"hello", http.StatusOK}, {"eval('alert(1)')", http.StatusForbidden}} {
		requestID := "eng1564-" + uuid.NewString()
		headers := map[string]string{"User-Agent": "eng1564-full-client/1.0", "X-Forwarded-For": "192.0.2.99, 203.0.113.42, 34.1.2.3", "X-Request-Id": requestID, "X-Prompt": "never-export-this", "X-Session-Id": "eng1564-" + collectorID, proxyAPIKeyHeader: "", "Authorization": "Bearer " + identityToken}
		status, responseHeaders, raw := proxyRequest(t, http.MethodPost, apiKey, path, headers, mustJSON(t, trustGuardChatRequest(tc.prompt)))
		require.Equal(t, tc.status, status, "%s", raw)
		traces[status] = responseHeaders.Get("X-AG-Trace-Id")
		requestIDs[status] = requestID
		require.NotEmpty(t, traces[status])
		if status == http.StatusForbidden {
			assert.Contains(t, string(raw), "code_injection")
		}
		t.Logf("SIEM_FULL_PIPELINE gateway_id=%s guard_id=%s collector_id=%s status=%d gateway_trace=%s request_id=%s", gatewayID, guardID, collectorID, status, traces[status], requestID)
	}
	assert.Equal(t, 1, up.Hits())
	fmt.Printf("SIEM_FULL_COLLECTOR=%s\n", collectorID)
	if os.Getenv("FUNCTIONAL_CLICKHOUSE_URL") != "" {
		assertSIEMStorage(t, tenantID, gatewayID, collectorID, traces, requestIDs)
	} else {
		time.Sleep(2 * time.Second)
	}
}

func assertSIEMStorage(t *testing.T, tenantID, gatewayID, collectorID string, traces, requestIDs map[int]string) {
	t.Helper()
	var guard, gate []map[string]any
	require.Eventually(t, func() bool {
		guard = siemClickHouseRows(t, "SELECT tenant_id,trace_id,correlation_id,session_id,user_id,user_email,ip,request_direction,status_outcome,security,request_headers,latency FROM default.trustguard_events WHERE collector_id='"+collectorID+"'")
		gate = siemClickHouseRows(t, "SELECT tenant_id,trace_id,principal_subject,principal_email,principal_method,ip,session_id,is_flagged,http_status,security FROM default.trustgate_events WHERE gateway_id='"+gatewayID+"'")
		return len(guard) == 3 && len(gate) == 2
	}, 15*time.Second, 250*time.Millisecond)
	for _, event := range gate {
		status := int(event["http_status"].(float64))
		assert.Equal(t, tenantID, event["tenant_id"])
		assert.Equal(t, "eng1564-"+collectorID, event["session_id"])
		assert.Equal(t, traces[status], event["trace_id"])
		assert.Equal(t, "eng1564-full-user", event["principal_subject"])
		assert.Equal(t, "full-user@example.test", event["principal_email"])
		assert.Equal(t, "external_jwt", event["principal_method"])
		assert.Equal(t, "203.0.113.42", event["ip"])
		wantSecurity := `[]`
		if status == http.StatusForbidden {
			wantSecurity = `["code_injection"]`
			assert.Equal(t, float64(1), event["is_flagged"])
		}
		assert.JSONEq(t, wantSecurity, event["security"].(string))
	}
	directions := make(map[string][]string)
	for _, event := range guard {
		status := http.StatusOK
		wantSecurity := `[]`
		if event["status_outcome"] == "block" {
			status, wantSecurity = http.StatusForbidden, `["code_injection"]`
		}
		assert.Equal(t, tenantID, event["tenant_id"])
		assert.Equal(t, "eng1564-"+collectorID, event["session_id"])
		assert.Equal(t, traces[status], event["correlation_id"])
		assert.Equal(t, "eng1564-full-user", event["user_id"])
		assert.Equal(t, "full-user@example.test", event["user_email"])
		assert.Equal(t, "203.0.113.42", event["ip"])
		assert.JSONEq(t, wantSecurity, event["security"].(string))
		var headers map[string][]string
		require.NoError(t, json.Unmarshal([]byte(event["request_headers"].(string)), &headers))
		assert.Equal(t, map[string][]string{"Content-Type": {"application/json"}, "User-Agent": {"eng1564-full-client/1.0"}, "X-Request-Id": {requestIDs[status]}}, headers)
		var latency map[string]int64
		require.NoError(t, json.Unmarshal([]byte(event["latency"].(string)), &latency))
		assert.GreaterOrEqual(t, latency["detectors_ms"], int64(0))
		assert.LessOrEqual(t, latency["detectors_ms"], latency["total_ms"])
		correlation := event["correlation_id"].(string)
		directions[correlation] = append(directions[correlation], event["request_direction"].(string))
	}
	assert.ElementsMatch(t, []string{"input", "output"}, directions[traces[http.StatusOK]])
	assert.Equal(t, []string{"input"}, directions[traces[http.StatusForbidden]])
}

func siemClickHouseRows(t *testing.T, query string) []map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, os.Getenv("FUNCTIONAL_CLICKHOUSE_URL"), strings.NewReader(query+" FORMAT JSONEachRow"))
	require.NoError(t, err)
	req.SetBasicAuth(getEnv("FUNCTIONAL_CLICKHOUSE_USER", "default"), os.Getenv("FUNCTIONAL_CLICKHOUSE_PASSWORD"))
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var rows []map[string]any
	decoder := json.NewDecoder(resp.Body)
	for {
		var row map[string]any
		err := decoder.Decode(&row)
		if err == io.EOF {
			return rows
		}
		require.NoError(t, err)
		rows = append(rows, row)
	}
}
