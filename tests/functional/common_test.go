package functional_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// uniqueName returns a name that cannot collide across runs or
// sibling tests in the same run.
func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, uuid.NewString()[:8])
}

// CreateGateway issues a POST /v1/gateways and returns the new id.
// Aborts the calling test on any failure.
func CreateGateway(t *testing.T, payload map[string]any) string {
	t.Helper()
	status, body := sendRequest(t, http.MethodPost, AdminURL+"/v1/gateways", nil, payload)
	require.Equal(t, http.StatusCreated, status, "create gateway failed: %v", body)

	id, ok := body["id"].(string)
	require.True(t, ok, "create response missing id: %v", body)
	require.NotEmpty(t, id)
	return id
}

// CreateBackend issues a POST /v1/gateways/:gateway_id/backends and returns
// the new backend id. Aborts the calling test on any failure.
func CreateBackend(t *testing.T, gatewayID string, payload map[string]any) string {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/backends", AdminURL, gatewayID)
	status, body := sendRequest(t, http.MethodPost, url, nil, payload)
	require.Equal(t, http.StatusCreated, status, "create backend failed: %v", body)

	id, ok := body["id"].(string)
	require.True(t, ok, "create backend response missing id: %v", body)
	require.NotEmpty(t, id)
	return id
}

// CreatePolicy issues a POST /v1/gateways/:gateway_id/policies and returns
// the new policy id. Aborts the calling test on any failure.
func CreatePolicy(t *testing.T, gatewayID string, payload map[string]any) string {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gatewayID)
	status, body := sendRequest(t, http.MethodPost, url, nil, payload)
	require.Equal(t, http.StatusCreated, status, "create policy failed: %v", body)

	id, ok := body["id"].(string)
	require.True(t, ok, "create policy response missing id: %v", body)
	require.NotEmpty(t, id)
	return id
}

// validPolicyPayload returns a minimal payload accepted by Validate() (name
// plus one enabled rate-limiter plugin in the pre_request stage). Callers
// may override fields.
func validPolicyPayload(name string) map[string]any {
	return map[string]any{
		"name": name,
		"plugins": []map[string]any{
			{
				"name":     "rate_limiter",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 0,
				"settings": map[string]any{"limit": 100},
			},
		},
	}
}

// CreateConsumer issues a POST /v1/gateways/:gateway_id/consumers and returns
// the new consumer id. Aborts the calling test on any failure.
func CreateConsumer(t *testing.T, gatewayID string, payload map[string]any) string {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gatewayID)
	status, body := sendRequest(t, http.MethodPost, url, nil, payload)
	require.Equal(t, http.StatusCreated, status, "create consumer failed: %v", body)

	id, ok := body["id"].(string)
	require.True(t, ok, "create consumer response missing id: %v", body)
	require.NotEmpty(t, id)
	return id
}

// validConsumerPayload returns a minimal payload accepted by Validate()
// (name, path, one backend reference). Callers may override fields.
func validConsumerPayload(name, backendID string) map[string]any {
	return map[string]any{
		"name":        name,
		"path":        "/v1/chat",
		"backend_ids": []string{backendID},
	}
}

// validBackendPayload returns a minimal payload accepted by Validate()
// (name, algorithm, one openai target with api_key auth). Callers may
// override fields.
func validBackendPayload(name string) map[string]any {
	return map[string]any{
		"name":      name,
		"algorithm": "round-robin",
		"targets": []map[string]any{
			{
				"provider": "openai",
				"weight":   1,
				"auth": map[string]any{
					"type":    "api_key",
					"api_key": map[string]any{"api_key": "sk-test"},
				},
			},
		},
	}
}

// sendRequest performs an HTTP call, JSON-encoding `body` when
// provided, and returns the status plus decoded JSON map (empty on
// 204).
func sendRequest(
	t *testing.T,
	method, url string,
	headers map[string]string,
	body any,
) (int, map[string]any) {
	t.Helper()

	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(buf)
	}

	req, err := http.NewRequest(method, url, reader)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, map[string]any{}
	}

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	out := map[string]any{}
	if len(raw) > 0 {
		// We deliberately tolerate non-JSON 5xx bodies in tests so we
		// surface the raw payload rather than masking the error.
		if jerr := json.Unmarshal(raw, &out); jerr != nil {
			out = map[string]any{"_raw": string(raw)}
		}
	}
	assert.NotNil(t, out)
	return resp.StatusCode, out
}
