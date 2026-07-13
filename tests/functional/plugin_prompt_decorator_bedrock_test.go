//go:build functional

package functional_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type promptBedrockRequest struct {
	method string
	path   string
	body   []byte
}

type promptBedrockStub struct {
	server   *httptest.Server
	mu       sync.Mutex
	requests []promptBedrockRequest
	err      error
}

func (s *promptBedrockStub) captureRequest(r *http.Request) []byte {
	raw, err := io.ReadAll(r.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.err = fmt.Errorf("read Bedrock request body: %w", err)
		return nil
	}
	s.requests = append(s.requests, promptBedrockRequest{
		method: r.Method,
		path:   r.URL.Path,
		body:   append([]byte(nil), raw...),
	})
	return raw
}

func (s *promptBedrockStub) captureWriteError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = fmt.Errorf("write Bedrock response: %w", err)
}

func (s *promptBedrockStub) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func (s *promptBedrockStub) lastRequest(t *testing.T) promptBedrockRequest {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NoError(t, s.err)
	require.NotEmpty(t, s.requests)
	request := s.requests[len(s.requests)-1]
	request.body = append([]byte(nil), request.body...)
	return request
}

func newPromptBedrockStub(t *testing.T) *promptBedrockStub {
	t.Helper()
	listener, err := net.Listen("tcp", strings.TrimPrefix(bedrockGuardrailEndpoint, "http://"))
	require.NoError(t, err)
	stub := &promptBedrockStub{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := stub.captureRequest(r)
		w.Header().Set("Content-Type", "application/json")
		response := `{"id":"chatcmpl-test","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"bedrock-response"},"finish_reason":"stop"}]}`
		if bytes.Contains(raw, []byte(`"anthropic_version"`)) {
			response = `{"id":"msg-test","type":"message","role":"assistant","model":"claude-test","content":[{"type":"text","text":"bedrock-response"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`
		}
		if _, err := io.WriteString(w, response); err != nil {
			stub.captureWriteError(err)
		}
	})
	stub.server = httptest.NewUnstartedServer(handler)
	require.NoError(t, stub.server.Listener.Close())
	stub.server.Listener = listener
	stub.server.Start()
	t.Cleanup(stub.server.Close)
	return stub
}

func bedrockPromptBackendPayload(name string) map[string]any {
	return map[string]any{
		"name":     name,
		"provider": "bedrock",
		"weight":   1,
		"auth": map[string]any{
			"type": "aws",
			"aws": map[string]any{
				"region":            "us-east-1",
				"access_key_id":     "functional-access-key",
				"secret_access_key": "functional-secret-key",
			},
		},
	}
}

func setupBedrockPromptRoute(t *testing.T, settings map[string]any) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("decorator-bedrock-gw")})
	backendID := CreateRegistry(t, gatewayID, bedrockPromptBackendPayload(uniqueName("bedrock")))
	policyID := createScopedPolicy(t, gatewayID, "prompt_decorator", settings, 0, false)
	path, apiKey := addConsumerRoute(t, gatewayID, backendID, policyID)
	return apiKey, path
}

func TestPluginE2E_PromptDecorator_BedrockProviderAdaptation(t *testing.T) {
	defer Track(t, "PromptDecorator")()

	stub := newPromptBedrockStub(t)
	settings := promptDecoratorSettings(
		promptSystemDecorator("bedrock-decoration", "append"),
		promptDecorator("end", "assistant", "bedrock-tail"),
	)
	tests := []struct {
		name       string
		model      string
		wantClaude bool
	}{
		{name: "claude", model: "anthropic.claude-3-5-sonnet-20241022-v2:0", wantClaude: true},
		{name: "openai compatible", model: "us.deepseek.deepseek-r1-v1:0"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			apiKey, path := setupBedrockPromptRoute(t, settings)
			body := mustJSON(t, chatBody([]map[string]any{
				{"role": "system", "content": "bedrock-base"},
				{"role": "user", "content": "bedrock-user"},
			}, map[string]any{"model": test.model, "max_tokens": 64}))
			requestsBefore := stub.requestCount()

			status, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil, body)
			request := stub.lastRequest(t)

			require.Equal(t, http.StatusOK, status)
			require.Equal(t, requestsBefore+1, stub.requestCount())
			assert.Equal(t, http.MethodPost, request.method)
			assert.Equal(t, "/model/"+test.model+"/invoke", request.path)
			forwarded := decodedPromptBody(t, request.body)
			if test.wantClaude {
				assert.Equal(t, "bedrock-2023-05-31", forwarded["anthropic_version"])
				assert.Equal(t, "bedrock-base\nbedrock-decoration", forwarded["system"])
				messages := decodedPromptMessages(t, request.body)
				require.Equal(t, []string{"user", "assistant"}, promptRoles(messages))
				assert.Equal(t, "bedrock-user", messages[0]["content"])
				assert.Equal(t, "bedrock-tail", messages[1]["content"])
				return
			}
			messages := decodedPromptMessages(t, request.body)
			require.Equal(t, []string{"system", "user", "assistant"}, promptRoles(messages))
			assert.Equal(t, "bedrock-base\nbedrock-decoration", messages[0]["content"])
			assert.Equal(t, "bedrock-user", messages[1]["content"])
			assert.Equal(t, "bedrock-tail", messages[2]["content"])
		})
	}
}
