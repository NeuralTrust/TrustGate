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
	sentimentSetID  = "0b9e3f2a-6c1d-4a7e-9b2f-3d4c5e6f7a8b"
	topicSetID      = "1c0f4a3b-7d2e-4b8f-8c3a-4e5d6f7a8b9c"
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
// traffic: it records what it is asked and always answers "negative" for the
// sentiment set, "billing" (not the catalog's spelling) for the topic set and
// a result for a set the consumer does not have.
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
			`{"results":[{"label_set_id":"`+sentimentSetID+`","label":"negative"},{"label_set_id":"`+topicSetID+`","label":"billing"},{"label_set_id":"made-up","label":"x"}]}`,
		)
	}))
	t.Cleanup(u.server.Close)
	return u
}

func (u *classifierUpstream) sawTogether(markers ...string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, b := range u.bodies {
		all := true
		for _, m := range markers {
			all = all && strings.Contains(b, m)
		}
		if all {
			return true
		}
	}
	return false
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

func consumerLabelSets() []map[string]any {
	return []map[string]any{
		{
			"id": sentimentSetID, "name": "Sentiment analysis", "instructions": "Classify the overall sentiment of the user's message",
			"labels": []map[string]any{
				{"name": "positive", "description": "Happy or satisfied"},
				{"name": "negative", "description": "Angry or disappointed"},
				{"name": "neutral"},
			},
		},
		{
			"id": topicSetID, "name": "Topic",
			"labels": []map[string]any{
				{"name": "Billing", "description": "Refunds, invoices and charges"},
				{"name": "Legal", "description": "Contracts and terms of service"},
			},
		},
	}
}

func labelSetsURL(gatewayID, consumerID string) string {
	return fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/label-sets", AdminURL, gatewayID, consumerID)
}

func putConsumerLabelSets(t *testing.T, gatewayID, consumerID string, sets []map[string]any) (int, map[string]any) {
	t.Helper()
	return sendRequest(t, http.MethodPut, labelSetsURL(gatewayID, consumerID), nil, map[string]any{"label_sets": sets})
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
	return setupLabelRouteTo(t, newJSONUpstream(t, "labels-upstream"), enabled, receiver, policies...)
}

func setupLabelRouteTo(t *testing.T, up *fakeUpstream, enabled bool, receiver *otlpReceiver, policies ...map[string]any) labelRoute {
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

	status, body = putConsumerLabelSets(t, gatewayID, consumerID, consumerLabelSets())
	require.Equal(t, http.StatusOK, status, "set consumer label sets failed: %v", body)

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

	assert.True(t, receiver.contains("trustgate.label.results"), "the event carries one result per label set")
	assert.True(t, receiver.contains(`{"label_set_id":"`+sentimentSetID+`","label_set_name":"Sentiment analysis","label":"negative"}`),
		"the sentiment set got its label")
	assert.True(t, receiver.contains(`{"label_set_id":"`+topicSetID+`","label_set_name":"Topic","label":"Billing"}`),
		"the topic set got its label, in the catalog's spelling")
	assert.False(t, receiver.contains("made-up"), "a set the consumer does not have is dropped")
	assert.False(t, receiver.contains("trustgate.label.matched"), "the single-label attributes are gone")
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

func TestTrafficLabelsE2E_ConsumerWithoutLabelSetsIsNotLabeled(t *testing.T) {
	defer Track(t, "TrafficLabels")()

	receiver := newOTLPReceiver(t)
	route := setupLabelRoute(t, true, receiver)
	status, body := putConsumerLabelSets(t, route.gatewayID, route.consumerID, []map[string]any{})
	require.Equal(t, http.StatusOK, status, "clear label sets failed: %v", body)
	assert.Equal(t, []any{}, body["label_sets"])
	marker := uniqueName("no-label-sets")

	time.Sleep(2 * time.Second)
	status = postUntilRouted(t, route.apiKey, route.path, chatWithUserText(marker))
	assert.Equal(t, http.StatusOK, status)
	time.Sleep(3 * time.Second)
	assert.False(t, route.classifier.sawText(marker), "a consumer whose label sets were cleared must not be labeled")
}

// consumerLabelSetsWithDefaults is consumerLabelSets as the API returns it:
// every field present, empty strings included.
func consumerLabelSetsWithDefaults() []map[string]any {
	sets := consumerLabelSets()
	for _, s := range sets {
		if _, ok := s["instructions"]; !ok {
			s["instructions"] = ""
		}
		for _, l := range s["labels"].([]map[string]any) {
			if _, ok := l["description"]; !ok {
				l["description"] = ""
			}
		}
	}
	return sets
}

func mustJSONString(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return string(raw)
}

func TestTrafficLabelsE2E_AdminAPI(t *testing.T) {
	defer Track(t, "TrafficLabels")()

	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("labels-api")})
	up := newJSONUpstream(t, "labels-api")
	registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be"), up.URL()))
	consumerID := CreateConsumerWithRegistries(t, gatewayID, uniqueName("cons"), registryID)

	consumerURL := fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gatewayID, consumerID)
	status, body := sendRequest(t, http.MethodGet, consumerURL, nil, nil)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, []any{}, body["label_sets"], "a consumer without label sets answers an empty list")

	status, body = putConsumerLabelSets(t, gatewayID, consumerID, consumerLabelSets())
	require.Equal(t, http.StatusOK, status, "%v", body)
	sets, ok := body["label_sets"].([]any)
	require.True(t, ok, "label_sets missing from the consumer response: %v", body)
	require.Len(t, sets, 2)
	assert.Equal(t, consumerID, body["id"], "the full consumer is returned")
	_, hasV1 := body["labels"]
	assert.False(t, hasV1, "the single-label field is gone")

	status, body = sendRequest(t, http.MethodGet, consumerURL, nil, nil)
	require.Equal(t, http.StatusOK, status)
	raw, err := json.Marshal(body["label_sets"])
	require.NoError(t, err)
	assert.JSONEq(t, mustJSONString(t, consumerLabelSetsWithDefaults()), string(raw))

	status, body = sendRequest(t, http.MethodPut, consumerURL, nil, map[string]any{"name": uniqueName("renamed"), "label_sets": []any{}})
	require.Equal(t, http.StatusOK, status, "%v", body)
	updated, ok := body["label_sets"].([]any)
	require.True(t, ok, "%v", body)
	assert.Len(t, updated, 2, "the generic consumer update never touches the label sets")

	set := func(id, name string, labels ...string) map[string]any {
		out := make([]map[string]any, len(labels))
		for i, l := range labels {
			out[i] = map[string]any{"name": l}
		}
		return map[string]any{"id": id, "name": name, "labels": out}
	}
	tooMany := make([]map[string]any, 11)
	for i := range tooMany {
		tooMany[i] = set(fmt.Sprintf("set-%d", i), fmt.Sprintf("Set %d", i), "a", "b")
	}
	tooManyLabels := make([]string, 21)
	for i := range tooManyLabels {
		tooManyLabels[i] = fmt.Sprintf("label-%d", i)
	}
	for name, sets := range map[string][]map[string]any{
		"more than 10 label sets":       tooMany,
		"a single label":                {set("a", "Topic", "billing")},
		"more than 20 labels":           {set("a", "Topic", tooManyLabels...)},
		"duplicated label names":        {set("a", "Topic", "Billing", "billing")},
		"duplicated label set names":    {set("a", "Same", "x", "y"), set("b", "same", "x", "y")},
		"a label name over 64 chars":    {set("a", "Topic", strings.Repeat("n", 65), "b")},
		"a label set without a name":    {set("a", "", "x", "y")},
		"a label set without an id":     {set("", "Topic", "x", "y")},
		"a label set name over 64 char": {set("a", strings.Repeat("n", 65), "x", "y")},
	} {
		status, _ = putConsumerLabelSets(t, gatewayID, consumerID, sets)
		assert.Equal(t, http.StatusUnprocessableEntity, status, "%s must be refused", name)
	}

	for name, payload := range map[string]any{
		"missing label_sets": map[string]any{},
		"null label_sets":    map[string]any{"label_sets": nil},
		"v1 labels field":    map[string]any{"labels": []any{}},
		"missing body":       nil,
	} {
		status, _ = sendRequest(t, http.MethodPut, labelSetsURL(gatewayID, consumerID), nil, payload)
		assert.Equal(t, http.StatusUnprocessableEntity, status, "%s must be refused", name)
	}
	status, body = sendRequest(t, http.MethodGet, consumerURL, nil, nil)
	require.Equal(t, http.StatusOK, status)
	assert.Len(t, body["label_sets"], 2, "a refused body leaves the label sets as they were")

	status, _ = sendRequest(t, http.MethodPut, fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/labels", AdminURL, gatewayID, consumerID), nil,
		map[string]any{"labels": []any{}})
	assert.Equal(t, http.StatusNotFound, status, "the single-label endpoint is gone")

	mcpConsumerID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("mcp-cons"), "type": "mcp"})
	status, _ = putConsumerLabelSets(t, gatewayID, mcpConsumerID, consumerLabelSets())
	assert.Equal(t, http.StatusUnprocessableEntity, status, "only LLM consumers can hold label sets")
	status, body = putConsumerLabelSets(t, gatewayID, mcpConsumerID, []map[string]any{})
	assert.Equal(t, http.StatusOK, status, "clearing an MCP consumer is allowed: %v", body)

	status, body = putConsumerLabelSets(t, gatewayID, consumerID, []map[string]any{})
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Equal(t, []any{}, body["label_sets"], "[] clears the label sets")

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

// A Responses continuation only carries its new turn; the conversation buffer
// gives the classifier the earlier turns of the chain too.
func TestTrafficLabelsE2E_ResponsesContinuationIsLabeledWithItsConversation(t *testing.T) {
	defer Track(t, "TrafficLabels")()

	prefix := uniqueName("labels-chain")
	route := setupLabelRouteTo(t, newResponsesUpstream(t, prefix), true, newOTLPReceiver(t))
	path := "/" + ConsumerSlug(t, route.consumerID) + "/v1/responses"
	first := uniqueName("first-turn")
	second := uniqueName("second-turn")

	status := postUntilRouted(t, route.apiKey, path, map[string]any{"model": "gpt-4o-mini", "input": first})
	require.Equal(t, http.StatusOK, status)
	require.Eventually(t, func() bool { return route.classifier.sawText(first) }, 20*time.Second, 200*time.Millisecond,
		"the first turn was never labeled")

	status, _, body := proxyRequest(t, http.MethodPost, route.apiKey, path, nil, mustJSON(t, map[string]any{
		"model": "gpt-4o-mini", "input": second, "previous_response_id": responseTurnID(prefix, 1),
	}))
	require.Equal(t, http.StatusOK, status, "body: %s", body)
	require.Eventually(t, func() bool { return route.classifier.sawTogether(first, second) }, 20*time.Second, 200*time.Millisecond,
		"the continuation must be labeled with the earlier turn of its conversation")
}

func responseTurnID(prefix string, n int) string {
	return fmt.Sprintf("resp_%s_%d", prefix, n)
}
