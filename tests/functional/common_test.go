//go:build functional

package functional_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const functionalGatewayBaseDomain = "gw.neuraltrust.ai"

var (
	gatewayHosts sync.Map
	proxyHosts   sync.Map
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
	slug, ok := body["slug"].(string)
	require.True(t, ok, "create response missing slug: %v", body)
	require.NotEmpty(t, slug)
	gatewayHosts.Store(id, slug+"."+functionalGatewayBaseDomain)
	return id
}

// CreateRegistry issues a POST /v1/gateways/:gateway_id/registries and returns
// the new backend id. Aborts the calling test on any failure.
func CreateRegistry(t *testing.T, gatewayID string, payload map[string]any) string {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/registries", AdminURL, gatewayID)
	status, body := sendRequest(t, http.MethodPost, url, nil, payload)
	require.Equal(t, http.StatusCreated, status, "create registry failed: %v", body)

	id, ok := body["id"].(string)
	require.True(t, ok, "create registry response missing id: %v", body)
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
// plus the rate-limiter plugin slug). With the 1:1 model a policy is a single
// configured plugin instance. Callers may override fields.
func validPolicyPayload(name string) map[string]any {
	return map[string]any{
		"name":     name,
		"slug":     "rate_limiter",
		"enabled":  true,
		"priority": 0,
		"settings": map[string]any{
			"limit":  100,
			"window": "1m",
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

// validConsumerPayload returns a minimal payload accepted by Validate() (name
// plus an exact-match path). Associations (registries, auths, policies) are
// attached after creation via the dedicated link endpoints. The path is derived
// from the (already unique) name so it stays unique per gateway. Callers may
// override fields.
func validConsumerPayload(name string) map[string]any {
	return map[string]any{
		"name": name,
		"path": "/v1/" + name,
	}
}

// CreateConsumerWithRegistries creates a base consumer and attaches each
// registry through the association endpoint, returning the consumer id. This is
// the common multi-step setup now that registries live outside the create body.
func CreateConsumerWithRegistries(t *testing.T, gatewayID, name string, registryIDs ...string) string {
	t.Helper()
	id := CreateConsumer(t, gatewayID, validConsumerPayload(name))
	for _, registryID := range registryIDs {
		AttachRegistry(t, gatewayID, id, registryID)
	}
	return id
}

// AttachRegistry links a registry to a consumer via the association endpoint,
// asserting the idempotent 204 contract.
func AttachRegistry(t *testing.T, gatewayID, consumerID, registryID string) {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/registries/%s",
		AdminURL, gatewayID, consumerID, registryID)
	status, body := sendRequest(t, http.MethodPost, url, nil, nil)
	require.Equal(t, http.StatusNoContent, status, "attach registry failed: %v", body)
}

// AttachAuth links an auth credential to a consumer via the association
// endpoint, asserting the idempotent 204 contract.
func AttachAuth(t *testing.T, gatewayID, consumerID, authID string) {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/auths/%s",
		AdminURL, gatewayID, consumerID, authID)
	status, body := sendRequest(t, http.MethodPost, url, nil, nil)
	require.Equal(t, http.StatusNoContent, status, "attach auth failed: %v", body)
}

// AttachPolicy links a policy to a consumer via the association endpoint,
// asserting the idempotent 204 contract.
func AttachPolicy(t *testing.T, gatewayID, consumerID, policyID string) {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/policies/%s",
		AdminURL, gatewayID, consumerID, policyID)
	status, body := sendRequest(t, http.MethodPost, url, nil, nil)
	require.Equal(t, http.StatusNoContent, status, "attach policy failed: %v", body)
}

// SetPolicyGlobal promotes a policy to gateway-wide scope, asserting the 200
// contract that echoes the updated policy.
func SetPolicyGlobal(t *testing.T, gatewayID, policyID string) {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/policies/%s/global", AdminURL, gatewayID, policyID)
	status, body := sendRequest(t, http.MethodPost, url, nil, nil)
	require.Equal(t, http.StatusOK, status, "set policy global failed: %v", body)
}

// UpdateConsumer issues a PUT /v1/gateways/:gateway_id/consumers/:id, asserting
// the 200 contract. Registry-referencing config (model_policies, fallback) is
// configured here, after the registries have been attached.
func UpdateConsumer(t *testing.T, gatewayID, consumerID string, payload map[string]any) {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gatewayID, consumerID)
	status, body := sendRequest(t, http.MethodPut, url, nil, payload)
	require.Equal(t, http.StatusOK, status, "update consumer failed: %v", body)
}

// CreateAuth issues a POST /v1/gateways/:gateway_id/auths and returns the
// new auth id. Aborts the calling test on any failure.
func CreateAuth(t *testing.T, gatewayID string, payload map[string]any) string {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gatewayID)
	status, body := sendRequest(t, http.MethodPost, url, nil, payload)
	require.Equal(t, http.StatusCreated, status, "create auth failed: %v", body)

	id, ok := body["id"].(string)
	require.True(t, ok, "create auth response missing id: %v", body)
	require.NotEmpty(t, id)
	return id
}

// validAuthPayload returns a minimal api_key auth payload. The key is generated
// server-side, so the body carries no config block.
func validAuthPayload(name string) map[string]any {
	return map[string]any{
		"name":    name,
		"type":    "api_key",
		"enabled": true,
	}
}

// CreateAPIKeyAuth creates an api_key credential and returns both its id and the
// one-time plaintext key the create response surfaces.
func CreateAPIKeyAuth(t *testing.T, gatewayID, name string) (string, string) {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gatewayID)
	status, body := sendRequest(t, http.MethodPost, url, nil, validAuthPayload(name))
	require.Equal(t, http.StatusCreated, status, "create api_key auth failed: %v", body)

	id, ok := body["id"].(string)
	require.True(t, ok, "create auth response missing id: %v", body)
	require.NotEmpty(t, id)
	key, ok := body["api_key"].(string)
	require.True(t, ok, "create auth response missing generated api_key: %v", body)
	require.NotEmpty(t, key)
	return id, key
}

// createAndAttachAPIKey creates an api_key credential, attaches it to consumerID
// and returns the plaintext key the proxy plane must present in HeaderAPIKey.
func createAndAttachAPIKey(t *testing.T, gatewayID, consumerID string) string {
	t.Helper()
	authID, key := CreateAPIKeyAuth(t, gatewayID, uniqueName("proxy-key"))
	AttachAuth(t, gatewayID, consumerID, authID)
	host, ok := gatewayHosts.Load(gatewayID)
	require.True(t, ok, "gateway host missing for %s", gatewayID)
	proxyHosts.Store(key, host.(string))
	return key
}

// validRegistryPayload returns a minimal payload accepted by Validate(): a
// single openai target (a backend IS a target now) with api_key auth. Callers
// may override fields.
func validRegistryPayload(name string) map[string]any {
	return map[string]any{
		"name":     name,
		"provider": "openai",
		"weight":   1,
		"auth": map[string]any{
			"type":    "api_key",
			"api_key": map[string]any{"api_key": "sk-test"},
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
	// Authenticate against the admin-plane auth middleware unless the caller
	// supplied its own Authorization header (e.g. to exercise a 401 path).
	if _, ok := headers["Authorization"]; !ok && AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+AdminToken)
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
