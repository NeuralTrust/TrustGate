//go:build functional

package functional_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

const (
	labelsEventName = "traffic_labels"
	labelsStreamKey = "{trafficlabels}:stream"
	billingLabelID  = "0b9e3f2a-6c1d-4a7e-9b2f-3d4c5e6f7a8b"
	legalLabelID    = "1c0f4a3b-7d2e-4b8f-8c3a-4e5d6f7a8b9c"
)

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

// classifierUpstream stands in for the LLM the gateway selected to label its
// traffic: it records what it is asked and always picks the billing label.
type classifierUpstream struct {
	server *httptest.Server
	mu     sync.Mutex
	bodies []string
}

func newClassifierUpstream(t *testing.T) *classifierUpstream {
	t.Helper()
	u := &classifierUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.bodies = append(u.bodies, string(raw))
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w,
			`{"id":"chatcmpl-labels","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}],"usage":{"prompt_tokens":120,"completion_tokens":9,"total_tokens":129}}`,
			`{"labels":["`+billingLabelID+`"]}`,
		)
	}))
	t.Cleanup(u.server.Close)
	return u
}

func (u *classifierUpstream) sawText(marker string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, b := range u.bodies {
		if strings.Contains(b, marker) {
			return true
		}
	}
	return false
}

func consumerLabels() []map[string]any {
	return []map[string]any{
		{"id": billingLabelID, "name": "Billing", "instructions": "Refunds, invoices and charges", "examples": []string{"where is my refund"}},
		{"id": legalLabelID, "name": "Legal", "instructions": "Contracts and terms of service"},
	}
}

func putConsumerLabels(t *testing.T, gatewayID, consumerID string, labels []map[string]any) (int, map[string]any) {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/labels", AdminURL, gatewayID, consumerID)
	return sendRequest(t, http.MethodPut, url, nil, map[string]any{"labels": labels})
}

func putGatewayLabeling(t *testing.T, gatewayID string, labeling any) (int, map[string]any) {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s", AdminURL, gatewayID)
	return sendRequest(t, http.MethodPut, url, nil, map[string]any{"traffic_labeling": labeling})
}

type labelRoute struct {
	gatewayID  string
	consumerID string
	apiKey     string
	path       string
	classifier *classifierUpstream
}

func setupLabelRoute(t *testing.T, enabled bool, receiver *otlpReceiver, policies ...map[string]any) labelRoute {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{
		"slug": uniqueName("labels-gw"),
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
	up := newJSONUpstream(t, "labels-upstream")
	backendID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be"), up.URL()))
	consumerID := CreateConsumerWithRegistries(t, gatewayID, uniqueName("cons"), backendID)
	for _, entry := range policies {
		payload := map[string]any{"name": uniqueName("pol")}
		for k, v := range entry {
			payload[k] = v
		}
		AttachPolicy(t, gatewayID, consumerID, CreatePolicy(t, gatewayID, payload))
	}

	classifier := newClassifierUpstream(t)
	classifierID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("classifier"), classifier.server.URL))
	status, body := putGatewayLabeling(t, gatewayID, map[string]any{
		"enabled":        enabled,
		"registry_id":    classifierID,
		"model":          "gpt-4o-mini",
		"message_window": 3,
	})
	require.Equal(t, http.StatusOK, status, "enable traffic labeling failed: %v", body)

	status, body = putConsumerLabels(t, gatewayID, consumerID, consumerLabels())
	require.Equal(t, http.StatusOK, status, "set consumer labels failed: %v", body)

	apiKey := createAndAttachAPIKey(t, gatewayID, consumerID)
	return labelRoute{gatewayID: gatewayID, consumerID: consumerID, apiKey: apiKey, path: chatCompletionsPath(t, consumerID), classifier: classifier}
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

func postUntilRouted(t *testing.T, apiKey, path string, body map[string]any) int {
	t.Helper()
	var status int
	require.Eventually(t, func() bool {
		status, _, _ = proxyRequest(t, http.MethodPost, apiKey, path, nil, mustJSON(t, body))
		return status != http.StatusNotFound && status != http.StatusUnauthorized
	}, 15*time.Second, 250*time.Millisecond, "the proxy never routed the new gateway")
	return status
}

func streamHolds(t *testing.T, text string) bool {
	t.Helper()
	entries, err := redisDB.XRange(context.Background(), labelsStreamKey, "-", "+").Result()
	require.NoError(t, err)
	for _, e := range entries {
		for _, v := range e.Values {
			if s, ok := v.(string); ok && strings.Contains(s, text) {
				return true
			}
		}
	}
	return false
}

func TestTrafficLabelsE2E_LabelsAndPublishesWithoutThePrompt(t *testing.T) {
	defer Track(t, "TrafficLabels")()

	receiver := newOTLPReceiver(t)
	route := setupLabelRoute(t, true, receiver)
	marker := uniqueName("secret-card-4111")

	status := postUntilRouted(t, route.apiKey, route.path, chatWithUserText(marker+" where is my refund"))
	assert.Equal(t, http.StatusOK, status)

	require.Eventually(t, func() bool { return route.classifier.sawText(marker) }, 20*time.Second, 200*time.Millisecond,
		"the request was never sent to the classifier model")
	require.Eventually(t, func() bool { return receiver.contains(labelsEventName) }, 30*time.Second, 250*time.Millisecond,
		"no traffic_labels event reached the gateway's collector")

	assert.True(t, receiver.contains(billingLabelID), "the event carries the matched label")
	assert.True(t, receiver.contains(route.consumerID), "and the consumer it was evaluated for")
	assert.False(t, receiver.contains(marker), "the prompt must never reach the collector")
	assert.False(t, receiver.contains("You are the ACME assistant"), "nor the system prompt")

	require.Eventually(t, func() bool { return !streamHolds(t, marker) }, 10*time.Second, 100*time.Millisecond,
		"the prompt must leave Redis once it is labeled")
}

func TestTrafficLabelsE2E_BlockedRequestIsStillLabeled(t *testing.T) {
	defer Track(t, "TrafficLabels")()

	receiver := newOTLPReceiver(t)
	route := setupLabelRoute(t, true, receiver, policyPlugin("request_size_limiter", map[string]any{
		"allowed_payload_size": 40,
		"size_unit":            "bytes",
	}))
	marker := uniqueName("blocked-" + strings.Repeat("x", 40))

	status := postUntilRouted(t, route.apiKey, route.path, chatWithUserText(marker))
	assert.Equal(t, http.StatusRequestEntityTooLarge, status, "the guardrail blocks the request")

	require.Eventually(t, func() bool { return route.classifier.sawText(marker) }, 20*time.Second, 200*time.Millisecond,
		"a request blocked by a PreRequest plugin must still be labeled")
}

func TestTrafficLabelsE2E_DisabledGatewayIsNotLabeled(t *testing.T) {
	defer Track(t, "TrafficLabels")()

	receiver := newOTLPReceiver(t)
	route := setupLabelRoute(t, false, receiver)
	marker := uniqueName("not-labeled")

	status := postUntilRouted(t, route.apiKey, route.path, chatWithUserText(marker))
	assert.Equal(t, http.StatusOK, status)

	time.Sleep(3 * time.Second)
	assert.False(t, route.classifier.sawText(marker), "a gateway without the feature must not reach the classifier")
	assert.False(t, receiver.contains(labelsEventName))
}

func TestTrafficLabelsE2E_ConsumerWithoutLabelsIsNotLabeled(t *testing.T) {
	defer Track(t, "TrafficLabels")()

	receiver := newOTLPReceiver(t)
	route := setupLabelRoute(t, true, receiver)
	status, body := putConsumerLabels(t, route.gatewayID, route.consumerID, []map[string]any{})
	require.Equal(t, http.StatusOK, status, "clear labels failed: %v", body)
	assert.Empty(t, body["labels"])
	marker := uniqueName("no-labels")

	time.Sleep(2 * time.Second)
	status = postUntilRouted(t, route.apiKey, route.path, chatWithUserText(marker))
	assert.Equal(t, http.StatusOK, status)
	time.Sleep(3 * time.Second)
	assert.False(t, route.classifier.sawText(marker), "a consumer whose labels were cleared must not be labeled")
}

func TestTrafficLabelsE2E_AdminAPI(t *testing.T) {
	defer Track(t, "TrafficLabels")()

	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("labels-api")})
	up := newJSONUpstream(t, "labels-api")
	registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be"), up.URL()))
	consumerID := CreateConsumerWithRegistries(t, gatewayID, uniqueName("cons"), registryID)

	status, body := putConsumerLabels(t, gatewayID, consumerID, consumerLabels())
	require.Equal(t, http.StatusOK, status, "%v", body)
	labels, ok := body["labels"].([]any)
	require.True(t, ok, "labels missing from the consumer response: %v", body)
	require.Len(t, labels, 2)
	assert.Equal(t, consumerID, body["id"], "the full consumer is returned")

	url := fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gatewayID, consumerID)
	status, body = sendRequest(t, http.MethodGet, url, nil, nil)
	require.Equal(t, http.StatusOK, status)
	raw, err := json.Marshal(body["labels"])
	require.NoError(t, err)
	assert.Contains(t, string(raw), billingLabelID)

	status, _ = putConsumerLabels(t, gatewayID, consumerID, []map[string]any{
		{"id": "a", "name": "Same", "instructions": "x"},
		{"id": "b", "name": "same", "instructions": "y"},
	})
	assert.Equal(t, http.StatusUnprocessableEntity, status, "names are unique ignoring case")

	status, body = putGatewayLabeling(t, gatewayID, map[string]any{"enabled": true, "registry_id": registryID, "model": "gpt-4o-mini"})
	require.Equal(t, http.StatusOK, status, "%v", body)
	labeling, ok := body["traffic_labeling"].(map[string]any)
	require.True(t, ok, "traffic_labeling missing from the gateway response: %v", body)
	assert.Equal(t, registryID, labeling["registry_id"])
	assert.EqualValues(t, 3, labeling["message_window"], "the default window is made explicit")
	assert.EqualValues(t, 1, labeling["sampling_rate"], "the default rate is made explicit")

	other := CreateGateway(t, map[string]any{"slug": uniqueName("labels-other")})
	foreign := CreateRegistry(t, other, openaiBackendPayload(uniqueName("be"), up.URL()))
	status, _ = putGatewayLabeling(t, gatewayID, map[string]any{"enabled": true, "registry_id": foreign, "model": "gpt-4o-mini"})
	assert.Equal(t, http.StatusUnprocessableEntity, status, "a registry of another gateway is refused")

	status, body = putGatewayLabeling(t, gatewayID, nil)
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Nil(t, body["traffic_labeling"], "an explicit null clears the config")
}
