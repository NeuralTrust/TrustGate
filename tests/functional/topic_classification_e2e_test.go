//go:build functional

package functional_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const topicEventName = "topic_classification"

// otlpReceiver stands in for a customer's OTel collector. It keeps every
// exported payload as raw bytes: protobuf stores strings verbatim, so the
// prompt leaking into any record would show up as a substring.
type otlpReceiver struct {
	server *httptest.Server
	mu     sync.Mutex
	bodies [][]byte
}

func newOTLPReceiver(t *testing.T) *otlpReceiver {
	t.Helper()
	r := &otlpReceiver{}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		raw, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.bodies = append(r.bodies, raw)
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *otlpReceiver) contains(needle string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.bodies {
		if bytes.Contains(b, []byte(needle)) {
			return true
		}
	}
	return false
}

func topicCatalog() []map[string]any {
	return []map[string]any{
		{"name": "billing", "definition": "Refunds, invoices and charges"},
		{"name": "legal", "definition": "Contracts and terms of service"},
	}
}

// setupTopicRoute wires a gateway with topic classification set as given and
// its own OTLP exporter pointing at receiver, one OpenAI-compatible backend
// and an api-key consumer, plus any policies. It returns the key and path.
func setupTopicRoute(t *testing.T, enabled bool, receiver *otlpReceiver, policies ...map[string]any) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{
		"slug": uniqueName("topics-gw"),
		"topic_classification": map[string]any{
			"enabled":        enabled,
			"topics":         topicCatalog(),
			"message_window": 3,
		},
		"telemetry": map[string]any{
			"exporters": []map[string]any{{
				"name": "customer-collector",
				"type": "otlp",
				"settings": map[string]any{
					"endpoint":    receiver.server.URL,
					"protocol":    "http/protobuf",
					"insecure":    true,
					"compression": "none",
				},
			}},
		},
	})
	up := newJSONUpstream(t, "topics-upstream")
	backendID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be"), up.URL()))
	consumerID := CreateConsumerWithRegistries(t, gatewayID, uniqueName("cons"), backendID)
	for _, entry := range policies {
		payload := map[string]any{"name": uniqueName("pol")}
		for k, v := range entry {
			payload[k] = v
		}
		AttachPolicy(t, gatewayID, consumerID, CreatePolicy(t, gatewayID, payload))
	}
	apiKey := createAndAttachAPIKey(t, gatewayID, consumerID)
	return apiKey, chatCompletionsPath(t, consumerID)
}

func chatWithUserText(text string) map[string]any {
	return map[string]any{
		"model": "gpt-4o-mini",
		"messages": []map[string]string{
			{"role": "system", "content": "You are the ACME assistant."},
			{"role": "user", "content": text},
		},
	}
}

// postUntilRouted retries the request until the proxy routes the gateway
// created a moment ago, giving it time to pick up the new config.
func postUntilRouted(t *testing.T, apiKey, path string, body map[string]any) int {
	t.Helper()
	var status int
	require.Eventually(t, func() bool {
		status, _, _ = proxyRequest(t, http.MethodPost, apiKey, path, nil, mustJSON(t, body))
		return status != http.StatusNotFound && status != http.StatusUnauthorized
	}, 15*time.Second, 250*time.Millisecond, "the proxy never routed the new gateway")
	return status
}

func TestTopicClassificationE2E_ClassifiesAndPublishesWithoutThePrompt(t *testing.T) {
	defer Track(t, "TopicClassification")()

	receiver := newOTLPReceiver(t)
	apiKey, path := setupTopicRoute(t, true, receiver)
	marker := uniqueName("secret-card-4111")

	status := postUntilRouted(t, apiKey, path, chatWithUserText(marker+" where is my refund"))
	assert.Equal(t, http.StatusOK, status)

	require.Eventually(t, func() bool { return topicGuardCalls.sawText(marker) }, 20*time.Second, 200*time.Millisecond,
		"the request was never sent to topic-guard")
	require.Eventually(t, func() bool { return receiver.contains(topicEventName) }, 30*time.Second, 250*time.Millisecond,
		"no topic_classification event reached the gateway's collector")

	assert.True(t, receiver.contains("billing"), "the event carries the classification")
	assert.False(t, receiver.contains(marker), "the prompt must never reach the collector")
	assert.False(t, receiver.contains("You are the ACME assistant"), "nor the system prompt")
}

func TestTopicClassificationE2E_BlockedRequestIsStillClassified(t *testing.T) {
	defer Track(t, "TopicClassification")()

	receiver := newOTLPReceiver(t)
	apiKey, path := setupTopicRoute(t, true, receiver, policyPlugin("request_size_limiter", map[string]any{
		"allowed_payload_size": 40,
		"size_unit":            "bytes",
	}))
	marker := uniqueName("blocked-" + strings.Repeat("x", 40))

	status := postUntilRouted(t, apiKey, path, chatWithUserText(marker))
	assert.Equal(t, http.StatusRequestEntityTooLarge, status, "the guardrail blocks the request")

	require.Eventually(t, func() bool { return topicGuardCalls.sawText(marker) }, 20*time.Second, 200*time.Millisecond,
		"a request blocked by a PreRequest plugin must still be classified")
}

func TestTopicClassificationE2E_DisabledGatewayIsNotClassified(t *testing.T) {
	defer Track(t, "TopicClassification")()

	receiver := newOTLPReceiver(t)
	apiKey, path := setupTopicRoute(t, false, receiver)
	marker := uniqueName("not-classified")

	status := postUntilRouted(t, apiKey, path, chatWithUserText(marker))
	assert.Equal(t, http.StatusOK, status)

	time.Sleep(3 * time.Second)
	assert.False(t, topicGuardCalls.sawText(marker), "a gateway without the feature must not reach topic-guard")
	assert.False(t, receiver.contains(topicEventName))
}
