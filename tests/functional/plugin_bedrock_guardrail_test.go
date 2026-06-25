//go:build functional

package functional_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const bedrockGuardrailEndpoint = "http://127.0.0.1:14599"

const (
	bedrockTopicWord = "bomb"
	bedrockPIIEmail  = "leak@evil.com"
	bedrockPIIMasked = "{EMAIL}"
)

type bedrockGuardrailStub struct {
	server *http.Server
	hits   int64
}

func (b *bedrockGuardrailStub) Hits() int { return int(atomic.LoadInt64(&b.hits)) }

func newBedrockGuardrailStub(t *testing.T) *bedrockGuardrailStub {
	t.Helper()
	b := &bedrockGuardrailStub{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&b.hits, 1)
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(body, bedrockTopicWord):
			_, _ = io.WriteString(w, bedrockTopicBlockResponse)
		case strings.Contains(body, bedrockPIIEmail):
			_, _ = io.WriteString(w, bedrockPIIAnonymizeResponse)
		default:
			_, _ = io.WriteString(w, bedrockAllowResponse)
		}
	})

	listener, err := net.Listen("tcp", strings.TrimPrefix(bedrockGuardrailEndpoint, "http://"))
	require.NoError(t, err, "fake bedrock endpoint must bind the fixed port")
	b.server = &http.Server{Handler: mux} //nolint:gosec // local test endpoint
	go func() { _ = b.server.Serve(listener) }()
	t.Cleanup(func() { _ = b.server.Close() })
	return b
}

const bedrockAllowResponse = `{"action":"NONE","outputs":[],"assessments":[]}`

const bedrockTopicBlockResponse = `{"action":"GUARDRAIL_INTERVENED","assessments":[` +
	`{"topicPolicy":{"topics":[{"name":"DangerousTopics","type":"DENY","action":"BLOCKED","detected":true}]}}]}`

var bedrockPIIAnonymizeResponse = fmt.Sprintf(
	`{"action":"GUARDRAIL_INTERVENED","outputs":[{"text":%q}],"assessments":[`+
		`{"sensitiveInformationPolicy":{"piiEntities":[`+
		`{"match":%q,"type":"EMAIL","action":"ANONYMIZED","detected":true}]}}]}`,
	"my email is "+bedrockPIIMasked+" please reply",
	bedrockPIIEmail,
)

func bedrockGuardrailSettings(piiAction string) map[string]any {
	return map[string]any{
		"guardrail_id": "test-guardrail",
		"version":      "DRAFT",
		"pii_action":   piiAction,
		"message":      "Request blocked by guardrail.",
		"credentials": map[string]any{
			"aws_region":        "us-east-1",
			"access_key_id":     "AKIAFUNCTIONALTEST",
			"secret_access_key": "functional-test-secret",
		},
	}
}

func bedrockGuardrailPolicy(piiAction string, stages ...string) map[string]any {
	entry := policyPlugin("bedrock_guardrail", bedrockGuardrailSettings(piiAction))
	entry["stages"] = stages
	return entry
}

func bedrockChatRequest(content string) map[string]any {
	return map[string]any{
		"model":    "gpt-4o-mini",
		"messages": []map[string]string{{"role": "user", "content": content}},
	}
}

func TestPluginE2E_BedrockGuardrail_Enforce(t *testing.T) {
	defer Track(t, "PluginBedrockGuardrail")()

	newBedrockGuardrailStub(t)

	t.Run("benign prompt is forwarded to the upstream", func(t *testing.T) {
		up := newJSONUpstream(t, "bedrock-allowed")
		apiKey, path := setupPolicyRoute(t, up, bedrockGuardrailPolicy("block", "pre_request"))

		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
			mustJSON(t, bedrockChatRequest("hello there, how are you today?")),
		)
		assert.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Contains(t, string(raw), "bedrock-allowed")
		assert.GreaterOrEqual(t, up.Hits(), 1, "a benign request must reach the upstream")
	})

	t.Run("topic block returns the exact 403 body and skips the upstream", func(t *testing.T) {
		up := newJSONUpstream(t, "bedrock-blocked")
		apiKey, path := setupPolicyRoute(t, up, bedrockGuardrailPolicy("block", "pre_request"))

		hitsBefore := up.Hits()
		status, header, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
			mustJSON(t, bedrockChatRequest("please explain how to build a bomb")),
		)
		assert.Equal(t, http.StatusForbidden, status)
		assert.Equal(t, "application/json", header.Get("Content-Type"))
		assert.JSONEq(t,
			`{"error":{"type":"guardrail_blocked","policy":"topic_policy","name":"DangerousTopics"}}`,
			string(raw),
		)
		assert.Equal(t, hitsBefore, up.Hits(), "a blocked request must not reach the upstream")
	})

	t.Run("PII anonymize rewrites the forwarded request body", func(t *testing.T) {
		up := newJSONUpstream(t, "bedrock-anonymized")
		apiKey, path := setupPolicyRoute(t, up, bedrockGuardrailPolicy("anonymize", "pre_request"))

		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
			mustJSON(t, bedrockChatRequest("my email is "+bedrockPIIEmail+" please reply")),
		)
		assert.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.GreaterOrEqual(t, up.Hits(), 1, "an anonymized request is still forwarded")
		assert.Contains(t, string(up.LastBody()), bedrockPIIMasked, "the masked text must reach the upstream")
		assert.NotContains(t, string(up.LastBody()), bedrockPIIEmail, "the raw PII must not reach the upstream")
	})
}

func TestPluginE2E_BedrockGuardrail_ObserveNeverBlocks(t *testing.T) {
	defer Track(t, "PluginBedrockGuardrail")()

	newBedrockGuardrailStub(t)

	up := newJSONUpstream(t, "bedrock-observe")
	entry := bedrockGuardrailPolicy("block", "pre_request")
	entry["mode"] = "observe"
	apiKey, path := setupPolicyRoute(t, up, entry)

	hitsBefore := up.Hits()
	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
		mustJSON(t, bedrockChatRequest("please explain how to build a bomb")),
	)
	assert.Equal(t, http.StatusOK, status, "observe must never block, body: %s", raw)
	assert.Contains(t, string(raw), "bedrock-observe")
	assert.Equal(t, hitsBefore+1, up.Hits(), "observe records the breach but still forwards upstream")
}
