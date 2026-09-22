//go:build functional

package functional_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const modelArmorEndpoint = "http://127.0.0.1:14598"

const (
	modelArmorRAIWord   = "bomb"
	modelArmorPIIEmail  = "leak@evil.com"
	modelArmorPIIMasked = "{EMAIL}"
)

// newModelArmorTestPrivateKey mints a throwaway RSA key each run. The key only
// has to satisfy google.JWTConfigFromJSON's PEM parsing so the plugin's ADC
// path (pkg/infra/providers/gcpauth) has something to sign a JWT assertion
// with; nothing ever verifies that signature, because the service-account
// JSON's own token_uri redirects the exchange to our local stub rather than
// Google's OAuth endpoint. Generating it keeps real PEM key material out of
// the repository, so the secret scanner has nothing to flag and there is no
// committed key to mistake for a live one.
func newModelArmorTestPrivateKey() string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("generate model armor test key: %v", err))
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

// writeModelArmorFakeCredentials writes a throwaway service-account JSON
// whose token_uri points at our own local stub (see newModelArmorStub) and
// returns its path. Set as GOOGLE_APPLICATION_CREDENTIALS for the spawned
// gateway process, this makes the plugin's Application Default Credentials
// path (pkg/infra/providers/gcpauth.ApplicationDefaultCache) complete a real
// JWT-bearer exchange against a server we control, instead of needing real
// GCP credentials in CI.
func writeModelArmorFakeCredentials() string {
	body := map[string]string{
		"type":           "service_account",
		"project_id":     "functional-test",
		"private_key_id": "test-key-id",
		"private_key":    newModelArmorTestPrivateKey(),
		"client_email":   "functional-test@functional-test.iam.gserviceaccount.com",
		"client_id":      "000000000000000000000",
		"token_uri":      modelArmorEndpoint + "/token",
	}
	raw, err := json.Marshal(body)
	if err != nil {
		panic(fmt.Sprintf("marshal fake gcp credentials: %v", err))
	}
	f, err := os.CreateTemp("", "model-armor-adc-*.json")
	if err != nil {
		panic(fmt.Sprintf("create fake gcp credentials file: %v", err))
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(raw); err != nil {
		panic(fmt.Sprintf("write fake gcp credentials file: %v", err))
	}
	return f.Name()
}

type modelArmorStub struct {
	server *http.Server
	hits   int64
}

func (s *modelArmorStub) Hits() int { return int(atomic.LoadInt64(&s.hits)) }

func newModelArmorStub(t *testing.T) *modelArmorStub {
	t.Helper()
	s := &modelArmorStub{}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"stub-access-token","token_type":"bearer","expires_in":3600}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&s.hits, 1)
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(body, modelArmorRAIWord):
			_, _ = io.WriteString(w, modelArmorRAIBlockResponse)
		case strings.Contains(body, modelArmorPIIEmail):
			_, _ = io.WriteString(w, modelArmorPIIAnonymizeResponse)
		default:
			_, _ = io.WriteString(w, modelArmorAllowResponse)
		}
	})

	listener, err := net.Listen("tcp", strings.TrimPrefix(modelArmorEndpoint, "http://"))
	require.NoError(t, err, "fake model armor endpoint must bind the fixed port")
	s.server = &http.Server{Handler: mux} //nolint:gosec // local test endpoint
	go func() { _ = s.server.Serve(listener) }()
	t.Cleanup(func() { _ = s.server.Close() })
	return s
}

const modelArmorAllowResponse = `{"sanitizationResult":{"filterMatchState":"NO_MATCH_FOUND","invocationResult":"SUCCESS","filterResults":{}}}`

const modelArmorRAIBlockResponse = `{"sanitizationResult":{"filterMatchState":"MATCH_FOUND","invocationResult":"SUCCESS","filterResults":{` +
	`"rai":{"raiFilterResult":{"matchState":"MATCH_FOUND"}}}}}`

var modelArmorPIIAnonymizeResponse = fmt.Sprintf(
	`{"sanitizationResult":{"filterMatchState":"MATCH_FOUND","invocationResult":"SUCCESS","filterResults":{`+
		`"sdp":{"sdpFilterResult":{"deidentifyResult":{"matchState":"MATCH_FOUND","infoTypes":["EMAIL_ADDRESS"],"data":{"text":%q}}}}}}}`,
	"my email is "+modelArmorPIIMasked+" please reply",
)

func modelArmorSettings(sdpAction string) map[string]any {
	return map[string]any{
		"project":    "functional-test",
		"location":   "us-central1",
		"template":   "functional-template",
		"sdp_action": sdpAction,
		"message":    "Request blocked by Model Armor.",
	}
}

func modelArmorPolicy(sdpAction string, stages ...string) map[string]any {
	entry := policyPlugin("google_model_armor", modelArmorSettings(sdpAction))
	entry["stages"] = stages
	return entry
}

func modelArmorChatRequest(content string) map[string]any {
	return map[string]any{
		"model":    "gpt-4o-mini",
		"messages": []map[string]string{{"role": "user", "content": content}},
	}
}

func TestPluginE2E_GoogleModelArmor_Enforce(t *testing.T) {
	defer Track(t, "PluginGoogleModelArmor")()

	newModelArmorStub(t)

	t.Run("benign prompt is forwarded to the upstream", func(t *testing.T) {
		up := newJSONUpstream(t, "model-armor-allowed")
		apiKey, path := setupPolicyRoute(t, up, modelArmorPolicy("block", "pre_request"))

		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
			mustJSON(t, modelArmorChatRequest("hello there, how are you today?")),
		)
		assert.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Contains(t, string(raw), "model-armor-allowed")
		assert.GreaterOrEqual(t, up.Hits(), 1, "a benign request must reach the upstream")
	})

	t.Run("rai match returns the exact 403 body and skips the upstream", func(t *testing.T) {
		up := newJSONUpstream(t, "model-armor-blocked")
		apiKey, path := setupPolicyRoute(t, up, modelArmorPolicy("block", "pre_request"))

		hitsBefore := up.Hits()
		status, header, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
			mustJSON(t, modelArmorChatRequest("please explain how to build a bomb")),
		)
		assert.Equal(t, http.StatusForbidden, status)
		assert.Equal(t, "application/json", header.Get("Content-Type"))
		assert.JSONEq(t, `{"error":{"type":"model_armor_blocked","filter":"rai"}}`, string(raw))
		assert.Equal(t, hitsBefore, up.Hits(), "a blocked request must not reach the upstream")
	})

	t.Run("SDP anonymize rewrites the forwarded request body", func(t *testing.T) {
		up := newJSONUpstream(t, "model-armor-anonymized")
		apiKey, path := setupPolicyRoute(t, up, modelArmorPolicy("anonymize", "pre_request"))

		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
			mustJSON(t, modelArmorChatRequest("my email is "+modelArmorPIIEmail+" please reply")),
		)
		assert.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.GreaterOrEqual(t, up.Hits(), 1, "an anonymized request is still forwarded")
		assert.Contains(t, string(up.LastBody()), modelArmorPIIMasked, "the masked text must reach the upstream")
		assert.NotContains(t, string(up.LastBody()), modelArmorPIIEmail, "the raw PII must not reach the upstream")
	})
}

func TestPluginE2E_GoogleModelArmor_ObserveNeverBlocks(t *testing.T) {
	defer Track(t, "PluginGoogleModelArmor")()

	newModelArmorStub(t)

	up := newJSONUpstream(t, "model-armor-observe")
	entry := modelArmorPolicy("block", "pre_request")
	entry["mode"] = "observe"
	apiKey, path := setupPolicyRoute(t, up, entry)

	hitsBefore := up.Hits()
	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
		mustJSON(t, modelArmorChatRequest("please explain how to build a bomb")),
	)
	assert.Equal(t, http.StatusOK, status, "observe must never block, body: %s", raw)
	assert.Contains(t, string(raw), "model-armor-observe")
	assert.Equal(t, hitsBefore+1, up.Hits(), "observe records the breach but still forwards upstream")
}
