//go:build functional

package functional_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
)

const functionalTenantID = "functional-tenant"

func gatewayBaseDomain() string {
	if GlobalConfig != nil && GlobalConfig.Server.GatewayBaseDomain != "" {
		return strings.Trim(strings.ToLower(strings.TrimSpace(GlobalConfig.Server.GatewayBaseDomain)), ".")
	}
	return "llm.neuraltrust.ai"
}

var (
	gatewayHosts  sync.Map
	mcpHosts      sync.Map
	proxyHosts    sync.Map
	consumerSlugs sync.Map
)

// uniqueName returns a name that cannot collide across runs or
// sibling tests in the same run.
func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, uuid.NewString()[:8])
}

// CreateGateway issues a POST /v1/gateways and returns the new id.
// Aborts the calling test on any failure. Platform admin tokens have no
// tenant claim, so a default tenant_id and stamped entitlements are injected
// when the payload omits them.
func CreateGateway(t *testing.T, payload map[string]any) string {
	t.Helper()
	if payload == nil {
		payload = map[string]any{}
	}
	if _, ok := payload["tenant_id"]; !ok {
		payload["tenant_id"] = functionalTenantID
	}
	if _, ok := payload["entitlements"]; !ok {
		// The API rejects stamped limits unless all three are set, and
		// max_instances caps gateways per tenant. Every test here shares one
		// tenant, so a small value would give the whole suite a budget that
		// the next test to be added would exhaust. Tests that exercise the cap
		// itself stamp their own entitlements.
		//
		// The plan counter is per tenant and every test here shares one tenant,
		// so the burst is a budget for the whole suite, not for one gateway. The
		// first stamped create also seeds the tenant's row, so every default
		// stamp in this package has to be this generous.
		payload["entitlements"] = functionalSuitePlan()
	}
	status, body := sendRequest(t, http.MethodPost, AdminURL+"/v1/gateways", nil, payload)
	require.Equal(t, http.StatusCreated, status, "create gateway failed: %v", body)

	id, ok := body["id"].(string)
	require.True(t, ok, "create response missing id: %v", body)
	require.NotEmpty(t, id)
	slug, ok := body["slug"].(string)
	require.True(t, ok, "create response missing slug: %v", body)
	require.NotEmpty(t, slug)
	gatewayHosts.Store(id, slug+"."+gatewayBaseDomain())
	if hosts, ok := body["hosts"].(map[string]any); ok {
		if mcp, ok := hosts["mcp"].(string); ok && mcp != "" {
			mcpHosts.Store(id, mcp)
		}
	}
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

	slug, ok := body["slug"].(string)
	require.True(t, ok, "create consumer response missing slug: %v", body)
	require.NotEmpty(t, slug)
	consumerSlugs.Store(id, slug)
	return id
}

// ConsumerSlug returns the auto-generated slug captured when the consumer was
// created through CreateConsumer.
func ConsumerSlug(t *testing.T, consumerID string) string {
	t.Helper()
	slug, ok := consumerSlugs.Load(consumerID)
	require.True(t, ok, "slug not captured for consumer %s", consumerID)
	return slug.(string)
}

// chatCompletionsPath returns the fixed OpenAI-compatible proxy route for the
// given consumer: /{consumer_slug}/v1/chat/completions.
func chatCompletionsPath(t *testing.T, consumerID string) string {
	t.Helper()
	return "/" + ConsumerSlug(t, consumerID) + "/v1/chat/completions"
}

// validConsumerPayload returns a minimal payload accepted by Validate().
// Associations (registries, auths, policies) are attached after creation via
// the dedicated link endpoints. The routing slug is generated server-side.
func validConsumerPayload(name string) map[string]any {
	return map[string]any{
		"name": name,
	}
}

// CreateConsumerWithRegistries creates a consumer with the given registries
// bound atomically through the nested registries array of the create body.
func CreateConsumerWithRegistries(t *testing.T, gatewayID, name string, registryIDs ...string) string {
	t.Helper()
	payload := validConsumerPayload(name)
	bindings := make([]map[string]any, 0, len(registryIDs))
	for _, registryID := range registryIDs {
		bindings = append(bindings, map[string]any{"id": registryID})
	}
	payload["registries"] = bindings
	return CreateConsumer(t, gatewayID, payload)
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

// SetPolicyMCPWide promotes a policy to every MCP consumer of the gateway and
// the MCP Store, asserting the 200 contract, and returns the echoed policy.
func SetPolicyMCPWide(t *testing.T, gatewayID, policyID string) map[string]any {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/policies/%s/mcp-wide", AdminURL, gatewayID, policyID)
	status, body := sendRequest(t, http.MethodPost, url, nil, nil)
	require.Equal(t, http.StatusOK, status, "set policy mcp-wide failed: %v", body)
	return body
}

// UpdateConsumer issues a PUT /v1/gateways/:gateway_id/consumers/:id, asserting
// the 200 contract. Registry-referencing config (nested registries policies,
// fallback) must reference registries already attached to the consumer.
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
	registerProxyKey(t, gatewayID, consumerID, authID, key)
	return key
}

func registerProxyKey(t *testing.T, gatewayID, consumerID, authID, key string) {
	t.Helper()
	AttachAuth(t, gatewayID, consumerID, authID)
	host, ok := gatewayHosts.Load(gatewayID)
	require.True(t, ok, "gateway host missing for %s", gatewayID)
	proxyHosts.Store(key, host.(string))
}

func userToken(t *testing.T, tenantID, userID string) string {
	t.Helper()
	now := time.Now()
	token, err := golangjwt.NewWithClaims(golangjwt.SigningMethodHS256, &jwt.Claims{
		TenantID: tenantID,
		UserID:   userID,
		RegisteredClaims: golangjwt.RegisteredClaims{
			IssuedAt:  golangjwt.NewNumericDate(now),
			ExpiresAt: golangjwt.NewNumericDate(now.Add(time.Hour)),
		},
	}).SignedString([]byte(GlobalConfig.Server.SecretKey))
	require.NoError(t, err)
	return token
}

// userTokenWithEmail is userToken carrying the user's email, as the console's
// tokens do.
func userTokenWithEmail(t *testing.T, tenantID, userID, email string) string {
	t.Helper()
	now := time.Now()
	token, err := golangjwt.NewWithClaims(golangjwt.SigningMethodHS256, &jwt.Claims{
		TenantID:  tenantID,
		UserID:    userID,
		UserEmail: email,
		RegisteredClaims: golangjwt.RegisteredClaims{
			IssuedAt:  golangjwt.NewNumericDate(now),
			ExpiresAt: golangjwt.NewNumericDate(now.Add(time.Hour)),
		},
	}).SignedString([]byte(GlobalConfig.Server.SecretKey))
	require.NoError(t, err)
	return token
}

func llmKeyRequest(t *testing.T, method, gatewayID, token, suffix string, body any) (int, map[string]any) {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/store/principal/llm-key%s", AdminURL, gatewayID, suffix)
	return sendRequest(t, method, url, map[string]string{"Authorization": "Bearer " + token}, body)
}

func GetLLMKey(t *testing.T, gatewayID, userID string) (int, map[string]any) {
	t.Helper()
	return llmKeyRequest(t, http.MethodGet, gatewayID, userToken(t, functionalTenantID, userID), "", nil)
}

func CreateLLMKey(t *testing.T, gatewayID, userID string, body any) (int, map[string]any) {
	t.Helper()
	return llmKeyRequest(t, http.MethodPost, gatewayID, userToken(t, functionalTenantID, userID), "", body)
}

func RotateLLMKey(t *testing.T, gatewayID, userID string, body any) (int, map[string]any) {
	t.Helper()
	return llmKeyRequest(t, http.MethodPost, gatewayID, userToken(t, functionalTenantID, userID), "/rotate", body)
}

func RevokeLLMKey(t *testing.T, gatewayID, userID string) int {
	t.Helper()
	status, _ := llmKeyRequest(t, http.MethodDelete, gatewayID, userToken(t, functionalTenantID, userID), "", nil)
	return status
}

func SetKeyBudget(t *testing.T, gatewayID, authID string, budget any) (int, map[string]any) {
	t.Helper()
	if budget == nil {
		budget = json.RawMessage("null")
	}
	url := fmt.Sprintf("%s/v1/gateways/%s/auths/%s/budget", AdminURL, gatewayID, authID)
	return sendRequest(t, http.MethodPut, url, nil, budget)
}

func monthlyBudget(limit float64) map[string]any {
	return map[string]any{"max": limit, "unit": "dollars", "time_window": "calendar_month"}
}

func CreatePersonalConsumer(t *testing.T, gatewayID string, payload map[string]any) string {
	t.Helper()
	payload["name"], payload["audience"] = uniqueName("personal"), "personal"
	url := fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gatewayID)
	status, body := sendRequest(t, http.MethodPost, url, nil, payload)
	require.Equal(t, http.StatusCreated, status, "create personal consumer failed: %v", body)
	require.Equal(t, "personal", body["audience"])
	id := fmt.Sprint(body["id"])
	consumerSlugs.Store(id, fmt.Sprint(body["slug"]))
	return id
}

func AttachAuthLink(t *testing.T, gatewayID, consumerID, authID, level string, priority int, grantedAt time.Time) {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/auths/%s", AdminURL, gatewayID, consumerID, authID)
	link := map[string]any{"level": level, "priority": priority, "granted_at": grantedAt.UTC().Format(time.RFC3339)}
	status, body := sendRequest(t, http.MethodPost, url, nil, link)
	require.Equal(t, http.StatusNoContent, status, "attach auth link failed: %v", body)
}

func DetachAuth(t *testing.T, gatewayID, consumerID, authID string) {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/auths/%s", AdminURL, gatewayID, consumerID, authID)
	status, body := sendRequest(t, http.MethodDelete, url, nil, nil)
	require.Equal(t, http.StatusNoContent, status, "detach auth failed: %v", body)
}

var storeAnthropicModels = []string{"opus-4.8", "opus-5.5"}

type switchableUpstream struct {
	*fakeUpstream
	failing atomic.Bool
}

func newSwitchableUpstream(t *testing.T, marker string) *switchableUpstream {
	t.Helper()
	u := &switchableUpstream{fakeUpstream: &fakeUpstream{}}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		w.Header().Set("Content-Type", "application/json")
		if u.failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"error":{"message":"upstream failure","type":"server_error"}}`)
			return
		}
		_, _ = fmt.Fprintf(w, `{"id":"chatcmpl-store","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}]}`, marker)
	}))
	t.Cleanup(u.server.Close)
	return u
}

type storeFixture struct {
	gatewayID string
	owner     string
	keyID     string
	key       string
	consumers map[string]string
	openaiA   *switchableUpstream
	deepseekA *fakeUpstream
	openaiD   *fakeUpstream
}

func storeGuard(consumer string) string {
	return "store-guard-" + strings.ToLower(consumer)
}

func storeRegistry(registryID string, allowed []string, defaultModel string) map[string]any {
	policy := map[string]any{"default": defaultModel}
	if allowed != nil {
		policy["allowed"] = allowed
	}
	return map[string]any{"registries": []map[string]any{{"id": registryID, "model_policies": policy}}}
}

func setupStoreFixture(t *testing.T, gateway map[string]any) *storeFixture {
	t.Helper()
	f := &storeFixture{
		gatewayID: CreateGateway(t, gateway),
		owner:     uniqueName("ana"),
		openaiA:   newSwitchableUpstream(t, "store-a-openai"),
		deepseekA: newJSONUpstream(t, "store-a-deepseek"),
		openaiD:   newJSONUpstream(t, "store-d-openai"),
	}
	openaiA := CreateRegistry(t, f.gatewayID, openaiBackendPayload(uniqueName("store-openai-a"), f.openaiA.URL()))
	deepseekA := CreateRegistry(t, f.gatewayID, openaiCompatibleBackendPayload(uniqueName("store-deepseek-a"), f.deepseekA.URL()))
	anthropic := CreateRegistry(t, f.gatewayID, anthropicBackendPayload(uniqueName("store-anthropic")))
	openaiD := CreateRegistry(t, f.gatewayID, openaiBackendPayload(uniqueName("store-openai-d"), f.openaiD.URL()))
	f.consumers = map[string]string{
		"A": CreatePersonalConsumer(t, f.gatewayID, map[string]any{
			"registries": []map[string]any{{"id": openaiA, "model_policies": map[string]any{"default": "gpt-4.1"}}, {"id": deepseekA}},
			"fallback":   map[string]any{"enabled": true, "triggers": []string{"http_5xx"}, "chain": []string{deepseekA}},
		}),
		"B": CreatePersonalConsumer(t, f.gatewayID, storeRegistry(anthropic, nil, "opus-4.8")),
		"C": CreatePersonalConsumer(t, f.gatewayID, storeRegistry(anthropic, []string{"opus-5.5"}, "opus-5.5")),
		"D": CreatePersonalConsumer(t, f.gatewayID, storeRegistry(openaiD, []string{"gpt6"}, "gpt6")),
	}
	for _, name := range []string{"B", "C"} {
		guard := CreatePolicy(t, f.gatewayID, map[string]any{
			"name": uniqueName("store-guard"), "slug": "model_allowlist", "enabled": true,
			"settings": map[string]any{"allowed_models": []string{storeGuard(name)}, "behavior_on_disallowed": "reject"},
		})
		AttachPolicy(t, f.gatewayID, f.consumers[name], guard)
	}
	status, created := CreateLLMKey(t, f.gatewayID, f.owner, llmKeyExpiry(30*llmKeyDay))
	require.Equal(t, http.StatusCreated, status, "body=%v", created)
	assert.Equal(t, []any{}, created["consumer_ids"])
	f.keyID, f.key = fmt.Sprint(created["id"]), fmt.Sprint(created["api_key"])
	grantedAt := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	for i, name := range []string{"A", "B", "C", "D"} {
		level := "group"
		if name == "D" {
			level = "user"
		}
		AttachAuthLink(t, f.gatewayID, f.consumers[name], f.keyID, level, 1, grantedAt.Add(time.Duration(i)*time.Hour))
	}
	return f
}

func gatewayCall(t *testing.T, base, gatewayID, key, method, path string, body any) (int, []byte) {
	t.Helper()
	return gatewayCallWithHeaders(t, base, gatewayID, key, method, path, body, nil)
}

func gatewayCallWithHeaders(t *testing.T, base, gatewayID, key, method, path string, body any, headers map[string]string) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(mustJSON(t, body))
	}
	req, err := http.NewRequest(method, base+path, reader)
	require.NoError(t, err)
	host, ok := gatewayHosts.Load(gatewayID)
	require.True(t, ok, "gateway host missing for %s", gatewayID)
	req.Host = host.(string)
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set(proxyAPIKeyHeader, key)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, raw
}

func storeChat(t *testing.T, base, gatewayID, key, model string) (int, string) {
	t.Helper()
	body := chatRequestNoModel()
	if model != "" {
		body = chatRequestModel(model)
	}
	status, raw := gatewayCall(t, base, gatewayID, key, http.MethodPost, "/store/v1/chat/completions", body)
	return status, string(raw)
}

func storeModelsStatus(t *testing.T, base, gatewayID, key string) int {
	t.Helper()
	status, _ := gatewayCall(t, base, gatewayID, key, http.MethodGet, "/store/v1/models", nil)
	return status
}

func storeModels(t *testing.T, base, gatewayID, key string) map[string]string {
	t.Helper()
	status, raw := gatewayCall(t, base, gatewayID, key, http.MethodGet, "/store/v1/models", nil)
	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	cards := map[string]string{}
	for _, card := range decodeModelsList(t, raw).Data {
		cards[card.ID] = card.OwnedBy
	}
	return cards
}

func eventuallyStore(t *testing.T, condition func() bool, msg string) {
	t.Helper()
	require.Eventually(t, condition, 20*time.Second, 200*time.Millisecond, msg)
}

func storeServes(t *testing.T, base string, f *storeFixture, model string, status int, marker string) func() bool {
	return func() bool {
		got, body := storeChat(t, base, f.gatewayID, f.key, model)
		return got == status && strings.Contains(body, marker)
	}
}

func assertWorkedExample(t *testing.T, base string, f *storeFixture) {
	t.Helper()
	cases := []struct {
		model  string
		status int
		marker string
	}{
		{"gpt-4.1", http.StatusForbidden, `"error":"model_not_allowed"`},
		{"gpt6", http.StatusOK, "store-d-openai"},
		{"opus-5.5", http.StatusForbidden, storeGuard("C")},
		{"opus-4.8", http.StatusForbidden, storeGuard("B")},
		{"", http.StatusOK, "store-d-openai"},
	}
	for _, tc := range cases {
		status, body := storeChat(t, base, f.gatewayID, f.key, tc.model)
		assert.Equal(t, tc.status, status, "model %q: %s", tc.model, body)
		assert.Contains(t, body, tc.marker, "model %q", tc.model)
	}
	assert.Contains(t, string(f.openaiD.LastBody()), `"gpt6"`, "a request without a model gets D's default")
	assert.Zero(t, f.openaiA.Hits()+f.deepseekA.Hits(), "D substitutes A's OpenAI, so A never serves")

	cards := storeModels(t, base, f.gatewayID, f.key)
	assert.Equal(t, "openai", cards["gpt6"])
	for _, id := range storeAnthropicModels {
		assert.Equal(t, "anthropic", cards[id], id)
	}
	for id, owner := range cards {
		if id != "gpt6" {
			assert.Equal(t, "anthropic", owner, "OpenAI lists only D's gpt6 and A's DeepSeek fallback never lists: %s", id)
		}
	}
}

func otlpStringAttr(key, value string) []byte {
	var str, kv []byte
	str = protowire.AppendString(protowire.AppendTag(str, 1, protowire.BytesType), value)
	kv = protowire.AppendString(protowire.AppendTag(kv, 1, protowire.BytesType), key)
	return protowire.AppendBytes(protowire.AppendTag(kv, 2, protowire.BytesType), str)
}

func protoFields(msg []byte, field protowire.Number) [][]byte {
	var out [][]byte
	for len(msg) > 0 {
		num, typ, n := protowire.ConsumeTag(msg)
		if n < 0 {
			return out
		}
		msg = msg[n:]
		if num == field && typ == protowire.BytesType {
			value, m := protowire.ConsumeBytes(msg)
			if m < 0 {
				return out
			}
			out, msg = append(out, value), msg[m:]
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, msg)
		if m < 0 {
			return out
		}
		msg = msg[m:]
	}
	return out
}

func otlpRecordWith(r *otlpReceiver, attrs ...[]byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, body := range r.bodies {
		for _, resource := range protoFields(body, 1) {
			for _, scope := range protoFields(resource, 2) {
				for _, record := range protoFields(scope, 2) {
					if !slices.ContainsFunc(attrs, func(attr []byte) bool { return !bytes.Contains(record, attr) }) {
						return true
					}
				}
			}
		}
	}
	return false
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

// responseWarnings returns the non-blocking warnings of an admin response, empty
// when it carries none.
func responseWarnings(body map[string]any) []string {
	raw, _ := body["warnings"].([]any)
	out := make([]string, 0, len(raw))
	for _, w := range raw {
		if text, ok := w.(string); ok {
			out = append(out, text)
		}
	}
	return out
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

// functionalSuitePlan is the plan the shared functional tenant runs under: no
// monthly cap and a burst the whole suite cannot reach in a minute.
//
// The first stamped create of a tenant seeds its tenant_entitlements row, and
// the seed is ON CONFLICT DO NOTHING. A database reused from an older run
// therefore keeps the functional-tenant row it already has, with whatever plan
// that run stamped (60 requests a minute, for instance), and the suite starts
// answering 429. The row has to be dropped before running against a reused
// local database:
//
//	DELETE FROM tenant_entitlements WHERE tenant_id = 'functional-tenant';
//
// (or recreate the database). A test that needs a small plan of its own must use
// its own tenant id, as TestPlanRateLimitE2E does.
func functionalSuitePlan() map[string]any {
	return map[string]any{
		"tier":            "enterprise",
		"burst_per_min":   1_000_000,
		"quota_per_month": 0,
		"max_instances":   1000,
	}
}
