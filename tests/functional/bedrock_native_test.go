//go:build functional

package functional_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	bedrockNativeAccessKey = "AKIAFUNCTIONALTEST"
	// clientSigV4 is what boto3 sends: a SigV4 signature for credentials the
	// gateway neither holds nor checks.
	clientSigV4 = "AWS4-HMAC-SHA256 Credential=AKIACLIENTONLY/20260101/us-east-1/bedrock/aws4_request, SignedHeaders=host;x-amz-date, Signature=deadbeef"

	bedrockNativeConverseAnswer   = `{"output":{"message":{"role":"assistant","content":[{"text":"native ok"}]}},"stopReason":"end_turn","usage":{"inputTokens":7,"outputTokens":3,"totalTokens":10}}`
	bedrockNativeInvokeAnswer     = `{"inputTextTokenCount":3,"results":[{"tokenCount":5,"outputText":"titan ok","completionReason":"FINISH"}]}`
	bedrockNativeAWSErrorBody     = `{"message":"Malformed input request, please reformat your input and try again."}`
	bedrockNativeModelInvalidBody = `{"message":"The provided model identifier is invalid."}`
	bedrockNativeProfileARN       = "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-3-5-sonnet-20241022-v2:0"
	bedrockNativeEncodedARN       = "arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Ainference-profile%2Fus.anthropic.claude-3-5-sonnet-20241022-v2%3A0"
)

type bedrockRuntimeCall struct {
	RequestURI string
	Header     http.Header
	Body       []byte
}

// bedrockRuntimeStub plays Bedrock Runtime on the endpoint the gateway binary
// is started with (AWS_ENDPOINT_URL_BEDROCK_RUNTIME). It records every call
// exactly as it arrived so a test can assert on the bytes the gateway sent.
type bedrockRuntimeStub struct {
	server *http.Server
	mu     sync.Mutex
	calls  []bedrockRuntimeCall
	frames [][]byte
	// cardFrames is the stream with a card number split across two deltas.
	cardFrames [][]byte
	// toolFrames is the stream whose tool call carries a card number split
	// across two fragments of its input.
	toolFrames [][]byte
}

func (s *bedrockRuntimeStub) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *bedrockRuntimeStub) last(t *testing.T) bedrockRuntimeCall {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.calls, "Bedrock saw no call")
	return s.calls[len(s.calls)-1]
}

func bedrockEventFrame(t *testing.T, eventType, payload string) []byte {
	t.Helper()
	var headers eventstream.Headers
	headers.Set(":message-type", eventstream.StringValue("event"))
	headers.Set(":event-type", eventstream.StringValue(eventType))
	headers.Set(":content-type", eventstream.StringValue("application/json"))
	var buf bytes.Buffer
	require.NoError(t, eventstream.NewEncoder().Encode(&buf, eventstream.Message{Headers: headers, Payload: []byte(payload)}))
	return buf.Bytes()
}

func newBedrockRuntimeStub(t *testing.T) *bedrockRuntimeStub {
	t.Helper()
	s := &bedrockRuntimeStub{}
	converseFrames := [][]byte{
		bedrockEventFrame(t, "messageStart", `{"role":"assistant"}`),
		bedrockEventFrame(t, "contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":"native "}}`),
		bedrockEventFrame(t, "contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":"stream"}}`),
		bedrockEventFrame(t, "messageStop", `{"stopReason":"end_turn"}`),
		bedrockEventFrame(t, "metadata", `{"usage":{"inputTokens":9,"outputTokens":4,"totalTokens":13},"metrics":{"latencyMs":5}}`),
	}
	chunk := base64.StdEncoding.EncodeToString([]byte(`{"outputText":"titan stream","index":0,"completionReason":"FINISH","inputTextTokenCount":3,"totalOutputTextTokenCount":4}`))
	invokeFrames := [][]byte{bedrockEventFrame(t, "chunk", `{"bytes":"`+chunk+`"}`)}

	// A card number split across two deltas, so no single frame carries it whole.
	cardFrames := [][]byte{
		bedrockEventFrame(t, "messageStart", `{"role":"assistant"}`),
		bedrockEventFrame(t, "contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":"Your test card is 42424242"}}`),
		bedrockEventFrame(t, "contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":"42424242 and that is all."}}`),
		bedrockEventFrame(t, "messageStop", `{"stopReason":"end_turn"}`),
	}

	toolFrames := [][]byte{
		bedrockEventFrame(t, "messageStart", `{"role":"assistant"}`),
		bedrockEventFrame(t, "contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":"Charging the card now."}}`),
		bedrockEventFrame(t, "contentBlockStop", `{"contentBlockIndex":0}`),
		bedrockEventFrame(t, "contentBlockStart", `{"contentBlockIndex":1,"start":{"toolUse":{"toolUseId":"tooluse_card","name":"charge"}}}`),
		bedrockEventFrame(t, "contentBlockDelta", `{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{\"card\":\"42424242"}}}`),
		bedrockEventFrame(t, "contentBlockDelta", `{"contentBlockIndex":1,"delta":{"toolUse":{"input":"42424242\",\"amount\":4242}"}}}`),
		bedrockEventFrame(t, "contentBlockStop", `{"contentBlockIndex":1}`),
		bedrockEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`),
	}

	s.cardFrames = cardFrames
	s.toolFrames = toolFrames
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.calls = append(s.calls, bedrockRuntimeCall{RequestURI: r.RequestURI, Header: r.Header.Clone(), Body: body})
		s.mu.Unlock()

		w.Header().Set("X-Amzn-Requestid", "stub-request-id")
		if bytes.Contains(body, []byte("trigger-aws-error")) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Amzn-Errortype", "ValidationException:http://internal.amazon.com/coral/com.amazon.bedrock/")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, bedrockNativeAWSErrorBody)
			return
		}
		if strings.Contains(r.URL.Path, "/no.such-model") {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Amzn-Errortype", "ValidationException:http://internal.amazon.com/coral/com.amazon.bedrock/")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, bedrockNativeModelInvalidBody)
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/converse"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, bedrockNativeConverseAnswer)
		case strings.HasSuffix(r.URL.Path, "/invoke"):
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Amzn-Bedrock-Input-Token-Count", "3")
			w.Header().Set("X-Amzn-Bedrock-Output-Token-Count", "5")
			_, _ = io.WriteString(w, bedrockNativeInvokeAnswer)
		case strings.HasSuffix(r.URL.Path, "/converse-stream"), strings.HasSuffix(r.URL.Path, "/invoke-with-response-stream"):
			frames := converseFrames
			if strings.HasSuffix(r.URL.Path, "/invoke-with-response-stream") {
				frames = invokeFrames
			}
			if bytes.Contains(body, []byte("card-stream")) {
				frames = cardFrames
			}
			if bytes.Contains(body, []byte("tool-stream")) {
				frames = toolFrames
			}
			w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
			w.WriteHeader(http.StatusOK)
			for _, f := range frames {
				_, _ = w.Write(f)
				w.(http.Flusher).Flush()
			}
		default:
			http.NotFound(w, r)
		}
	})
	s.frames = converseFrames

	listener, err := net.Listen("tcp", strings.TrimPrefix(bedrockGuardrailEndpoint, "http://"))
	require.NoError(t, err, "fake bedrock endpoint must bind the fixed port")
	s.server = &http.Server{Handler: mux} //nolint:gosec // local test endpoint
	go func() { _ = s.server.Serve(listener) }()
	t.Cleanup(func() { _ = s.server.Close() })
	return s
}

func bedrockNativeRegistryPayload(name string) map[string]any {
	return map[string]any{
		"name":     name,
		"provider": "bedrock",
		"weight":   1,
		"auth": map[string]any{
			"type": "aws",
			"aws": map[string]any{
				"region":            "us-east-1",
				"access_key_id":     bedrockNativeAccessKey,
				"secret_access_key": "functional-test-secret",
			},
		},
	}
}

// setupBedrockNativeRoute wires a consumer over one Bedrock registry, with the
// given policies attached. It returns the proxy credential and the consumer
// slug the native routes are mounted under.
func setupBedrockNativeRoute(t *testing.T, policies ...map[string]any) (apiKey, slug string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("bedrock-native-gw")})
	registryID := CreateRegistry(t, gatewayID, bedrockNativeRegistryPayload(uniqueName("bedrock")))
	consumerID := CreateConsumerWithRegistries(t, gatewayID, uniqueName("cons"), registryID)
	for _, entry := range policies {
		payload := map[string]any{"name": uniqueName("pol")}
		for k, v := range entry {
			payload[k] = v
		}
		AttachPolicy(t, gatewayID, consumerID, CreatePolicy(t, gatewayID, payload))
	}
	return createAndAttachAPIKey(t, gatewayID, consumerID), ConsumerSlug(t, consumerID)
}

func withStages(entry map[string]any, stages ...string) map[string]any {
	entry["stages"] = stages
	return entry
}

// readFrames splits a body into the eventstream frames it holds, failing on
// anything that is not a whole frame.
func readFrames(t *testing.T, body []byte) [][]byte {
	t.Helper()
	var frames [][]byte
	rest := body
	for len(rest) > 0 {
		require.GreaterOrEqual(t, len(rest), 16, "trailing bytes are not a frame")
		total := int(rest[0])<<24 | int(rest[1])<<16 | int(rest[2])<<8 | int(rest[3])
		require.LessOrEqual(t, total, len(rest), "truncated frame")
		frames = append(frames, rest[:total])
		rest = rest[total:]
	}
	return frames
}

func nativeHeaders() map[string]string {
	return map[string]string{"Authorization": clientSigV4, "Accept": "application/json"}
}

// A body no re-serialiser would reproduce: odd spacing, a trailing newline and
// keys out of order.
const bedrockNativeBody = "{ \"messages\" : [ {\"role\":\"user\", \"content\":[{\"text\":\"hi there\"}]} ],\n  \"zz\":1, \"inferenceConfig\":{\"maxTokens\":50} }\n"

func TestBedrockNative_Converse(t *testing.T) {
	defer Track(t, "BedrockNativeConverse")()
	stub := newBedrockRuntimeStub(t)
	apiKey, slug := setupBedrockNativeRoute(t)

	status, header, raw := proxyRequest(t, http.MethodPost, apiKey,
		"/"+slug+"/model/amazon.nova-lite-v1%3A0/converse", nativeHeaders(), []byte(bedrockNativeBody))

	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	assert.Equal(t, bedrockNativeConverseAnswer, string(raw), "the answer is AWS's, byte for byte")
	assert.Equal(t, "application/json", header.Get("Content-Type"))
	assert.Equal(t, "stub-request-id", header.Get("X-Amzn-Requestid"))

	got := stub.last(t)
	assert.Equal(t, bedrockNativeBody, string(got.Body), "Bedrock must receive the request bytes exactly as sent")
	assert.Equal(t, "/model/amazon.nova-lite-v1%3A0/converse", got.RequestURI, "the identifier is forwarded as received")
	auth := got.Header.Get("Authorization")
	assert.Contains(t, auth, "Credential="+bedrockNativeAccessKey+"/", "the call is signed with the registry's credentials")
	assert.Contains(t, auth, "/us-east-1/bedrock/aws4_request")
	assert.NotContains(t, auth, "AKIACLIENTONLY", "the client's own signature must never reach AWS")
	assert.Empty(t, got.Header.Get(proxyAPIKeyHeader), "the gateway credential must never reach AWS")
}

func TestBedrockNative_ConverseStream(t *testing.T) {
	defer Track(t, "BedrockNativeConverseStream")()
	stub := newBedrockRuntimeStub(t)
	apiKey, slug := setupBedrockNativeRoute(t)

	status, header, raw := proxyRequest(t, http.MethodPost, apiKey,
		"/"+slug+"/model/amazon.nova-lite-v1%3A0/converse-stream", nativeHeaders(), []byte(bedrockNativeBody))

	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	assert.Equal(t, "application/vnd.amazon.eventstream", header.Get("Content-Type"))
	assert.Equal(t, stub.frames, readFrames(t, raw), "every eventstream frame must arrive identical: not converted to SSE")
	assert.NotContains(t, string(raw), "data:")
	assert.Equal(t, bedrockNativeBody, string(stub.last(t).Body))
}

func TestBedrockNative_Invoke(t *testing.T) {
	defer Track(t, "BedrockNativeInvoke")()
	stub := newBedrockRuntimeStub(t)
	apiKey, slug := setupBedrockNativeRoute(t)
	body := `{"inputText":"tell me a story", "textGenerationConfig":{"maxTokenCount":50}}`

	status, header, raw := proxyRequest(t, http.MethodPost, apiKey,
		"/"+slug+"/model/amazon.titan-text-express-v1/invoke", nativeHeaders(), []byte(body))

	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	assert.Equal(t, bedrockNativeInvokeAnswer, string(raw))
	assert.Equal(t, "3", header.Get("X-Amzn-Bedrock-Input-Token-Count"), "the accounting headers are relayed")
	assert.Equal(t, "5", header.Get("X-Amzn-Bedrock-Output-Token-Count"))
	assert.Equal(t, body, string(stub.last(t).Body))
}

func TestBedrockNative_InvokeWithResponseStream(t *testing.T) {
	defer Track(t, "BedrockNativeInvokeStream")()
	stub := newBedrockRuntimeStub(t)
	apiKey, slug := setupBedrockNativeRoute(t)

	status, header, raw := proxyRequest(t, http.MethodPost, apiKey,
		"/"+slug+"/model/amazon.titan-text-express-v1/invoke-with-response-stream", nativeHeaders(), []byte(`{"inputText":"hi"}`))

	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	assert.Equal(t, "application/vnd.amazon.eventstream", header.Get("Content-Type"))
	frames := readFrames(t, raw)
	require.Len(t, frames, 1)
	msg, err := eventstream.NewDecoder().Decode(bytes.NewReader(frames[0]), nil)
	require.NoError(t, err)
	assert.Equal(t, "chunk", msg.Headers.Get(":event-type").String())
	assert.Equal(t, `{"inputText":"hi"}`, string(stub.last(t).Body))
}

func TestBedrockNative_ARNIdentifiers(t *testing.T) {
	defer Track(t, "BedrockNativeARN")()
	stub := newBedrockRuntimeStub(t)
	apiKey, slug := setupBedrockNativeRoute(t)

	t.Run("encoded ARN is forwarded as received", func(t *testing.T) {
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey,
			"/"+slug+"/model/"+bedrockNativeEncodedARN+"/converse", nativeHeaders(), []byte(bedrockNativeBody))
		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Equal(t, "/model/"+bedrockNativeEncodedARN+"/converse", stub.last(t).RequestURI)
	})

	t.Run("raw ARN has only its slash escaped", func(t *testing.T) {
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey,
			"/"+slug+"/model/"+bedrockNativeProfileARN+"/invoke", nativeHeaders(), []byte(`{"prompt":"hi"}`))
		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Equal(t,
			"/model/arn:aws:bedrock:us-east-1:123456789012:inference-profile%2Fus.anthropic.claude-3-5-sonnet-20241022-v2:0/invoke",
			stub.last(t).RequestURI)
	})

	t.Run("a traversal identifier never reaches AWS", func(t *testing.T) {
		before := stub.callCount()
		status, header, raw := proxyRequest(t, http.MethodPost, apiKey,
			"/"+slug+"/model/%2e%2e/converse", nativeHeaders(), []byte(`{}`))
		assert.Equal(t, http.StatusBadRequest, status, "body: %s", raw)
		assert.Equal(t, "ValidationException", header.Get("X-Amzn-Errortype"))
		assert.Equal(t, before, stub.callCount())
	})
}

func TestBedrockNative_AWSErrorsPassThrough(t *testing.T) {
	defer Track(t, "BedrockNativeAWSError")()
	newBedrockRuntimeStub(t)
	apiKey, slug := setupBedrockNativeRoute(t)

	status, header, raw := proxyRequest(t, http.MethodPost, apiKey,
		"/"+slug+"/model/amazon.nova-lite-v1:0/converse", nativeHeaders(), []byte(`{"messages":[],"x":"trigger-aws-error"}`))

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, bedrockNativeAWSErrorBody, string(raw), "AWS's error body must not be rewritten")
	assert.Equal(t, "ValidationException:http://internal.amazon.com/coral/com.amazon.bedrock/", header.Get("X-Amzn-Errortype"),
		"boto3 reads the error class from this header, so it must survive")
	assert.Equal(t, "stub-request-id", header.Get("X-Amzn-Requestid"))
}

func TestBedrockNative_PoliciesMaskAndBlock(t *testing.T) {
	defer Track(t, "BedrockNativePolicies")()
	stub := newBedrockRuntimeStub(t)
	apiKey, slug := setupBedrockNativeRoute(t,
		withStages(policyPlugin("regex_replace", map[string]any{
			"target": "request",
			"rules":  []map[string]any{{"pattern": "secret", "replacement": "[REDACTED]"}},
		}), "pre_request"),
		policyPlugin("model_allowlist", map[string]any{
			"allowed_models":         []string{"amazon.nova-*"},
			"behavior_on_disallowed": "reject",
		}),
	)

	t.Run("a masking policy masks the request and forwards the rest as sent", func(t *testing.T) {
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey,
			"/"+slug+"/model/amazon.nova-lite-v1:0/converse", nativeHeaders(),
			[]byte(`{"messages":[{"role":"user","content":[{"text":"my secret code"}]}],"additionalModelRequestFields":{"copy":"another secret"},"inferenceConfig":{"temperature":0.1}}`))
		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		got := string(stub.last(t).Body)
		assert.NotContains(t, got, "secret", "no copy of the removed text reaches Bedrock")
		assert.Contains(t, got, "my [REDACTED] code")
		assert.Contains(t, got, "another [REDACTED]", "an unmodelled copy is masked too")
		assert.Contains(t, got, `"temperature":0.1`)
	})

	t.Run("an InvokeModel prompt is masked in its own shape", func(t *testing.T) {
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey,
			"/"+slug+"/model/amazon.nova-lite-v1:0/invoke", nativeHeaders(), []byte(`{"prompt":"my secret code","max_gen_len":10}`))
		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.JSONEq(t, `{"prompt":"my [REDACTED] code","max_gen_len":10}`, string(stub.last(t).Body))
	})

	t.Run("a clean request keeps its bytes", func(t *testing.T) {
		const body = "{ \"messages\":[{\"role\":\"user\",\"content\":[{\"text\":\"nothing sensitive\"}]}],\n \"z\":1 }"
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey,
			"/"+slug+"/model/amazon.nova-lite-v1:0/converse", nativeHeaders(), []byte(body))
		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Equal(t, body, string(stub.last(t).Body), "a policy that finds nothing must leave the bytes alone")
	})

	t.Run("a model outside the allowlist is refused from the path", func(t *testing.T) {
		before := stub.callCount()
		status, header, raw := proxyRequest(t, http.MethodPost, apiKey,
			"/"+slug+"/model/meta.llama3-8b-instruct-v1:0/converse", nativeHeaders(),
			[]byte(`{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`))
		require.Equal(t, http.StatusForbidden, status, "body: %s", raw)
		assert.Equal(t, "AccessDeniedException", header.Get("X-Amzn-Errortype"))
		assert.Equal(t, before, stub.callCount())
	})
}

func TestBedrockNative_AuthErrorsUseTheAWSEnvelope(t *testing.T) {
	defer Track(t, "BedrockNativeAuth")()
	newBedrockRuntimeStub(t)
	apiKey, slug := setupBedrockNativeRoute(t)
	host, ok := proxyHosts.Load(apiKey)
	require.True(t, ok)

	// Only the SigV4 signature, no gateway key: the SDK default when nobody
	// configured the gateway credential.
	req, err := http.NewRequest(http.MethodPost, ProxyURL+"/"+slug+"/model/amazon.nova-lite-v1:0/converse", strings.NewReader(`{}`))
	require.NoError(t, err)
	req.Host = host.(string)
	req.Header.Set("Authorization", clientSigV4)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "body: %s", raw)
	assert.Equal(t, "UnrecognizedClientException", resp.Header.Get("X-Amzn-Errortype"))
}

func TestBedrockNative_ConsumerWithoutABedrockRegistry(t *testing.T) {
	defer Track(t, "BedrockNativeNoRegistry")()
	stub := newBedrockRuntimeStub(t)
	up := newJSONUpstream(t, "openai-only")
	apiKey, path := setupPolicyRoute(t, up, policyPlugin("rate_limiter", map[string]any{"limit": 100, "window": "1m"}))
	slug := strings.Split(strings.TrimPrefix(path, "/"), "/")[0]

	status, header, raw := proxyRequest(t, http.MethodPost, apiKey,
		"/"+slug+"/model/amazon.nova-lite-v1:0/converse", nativeHeaders(), []byte(`{"messages":[]}`))

	assert.Equal(t, http.StatusNotFound, status, "body: %s", raw)
	assert.Equal(t, "ResourceNotFoundException", header.Get("X-Amzn-Errortype"))
	assert.Equal(t, 0, up.Hits(), "a native Bedrock call must never be translated for another provider")
	assert.Equal(t, 0, stub.callCount())
}

// AWS answers an unknown model with a 400 the gateway reads as a model miss. The
// caller must still get that answer, and its error type, not a gateway 404.
func TestBedrockNative_UnknownModelRelaysAWSsOwnError(t *testing.T) {
	defer Track(t, "BedrockNativeUnknownModel")()
	stub := newBedrockRuntimeStub(t)
	apiKey, slug := setupBedrockNativeRoute(t)

	status, header, raw := proxyRequest(t, http.MethodPost, apiKey,
		"/"+slug+"/model/no.such-model-v1:0/converse", nativeHeaders(), []byte(`{"messages":[]}`))

	assert.Equal(t, http.StatusBadRequest, status, "body: %s", raw)
	assert.Equal(t, bedrockNativeModelInvalidBody, string(raw))
	assert.Equal(t, "ValidationException:http://internal.amazon.com/coral/com.amazon.bedrock/", header.Get("X-Amzn-Errortype"))
	assert.Equal(t, "stub-request-id", header.Get("X-Amzn-Requestid"))
	assert.Equal(t, 1, stub.callCount())
}

// A native stream is inspected like any other: text that a masking policy would
// rewrite stops the stream, because a native frame is never re-encoded.
func TestBedrockNative_StreamedOutputIsInspected(t *testing.T) {
	defer Track(t, "BedrockNativeStreamGuard")()
	stub := newBedrockRuntimeStub(t)
	apiKey, slug := setupBedrockNativeRoute(t, regexReplacePolicy(
		regexReplaceSettings("response", []map[string]any{{"pattern": regexStreamCardPattern, "replacement": "[CARD]"}}),
		"pre_response"))

	t.Run("a clean stream is relayed byte for byte", func(t *testing.T) {
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey,
			"/"+slug+"/model/amazon.nova-lite-v1:0/converse-stream", nativeHeaders(), []byte(bedrockNativeBody))
		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Equal(t, stub.frames, readFrames(t, raw))
	})

	t.Run("text the policy masks is masked in the frames", func(t *testing.T) {
		status, header, raw := proxyRequest(t, http.MethodPost, apiKey,
			"/"+slug+"/model/amazon.nova-lite-v1:0/converse-stream", nativeHeaders(),
			[]byte(`{"messages":[{"role":"user","content":[{"text":"card-stream"}]}]}`))
		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Equal(t, "application/vnd.amazon.eventstream", header.Get("Content-Type"))
		assert.NotContains(t, string(raw), regexStreamCardNumber)
		assert.NotContains(t, string(raw), "42424242 and", "no part of the card number may reach the client")

		// Read the frames the way an SDK does: whole frames, checksums verified,
		// the payload of each a JSON event.
		frames := readFrames(t, raw)
		require.Len(t, frames, len(stub.cardFrames), "no frame is dropped, only emptied")
		var text strings.Builder
		for i, f := range frames {
			msg, err := eventstream.NewDecoder().Decode(bytes.NewReader(f), nil)
			require.NoError(t, err, "frame %d must be well formed", i)
			assert.Equal(t, "event", msg.Headers.Get(":message-type").String())
			var ev struct {
				Delta struct {
					Text string `json:"text"`
				} `json:"delta"`
			}
			require.NoError(t, json.Unmarshal(msg.Payload, &ev), "frame %d payload", i)
			text.WriteString(ev.Delta.Text)
		}
		assert.Equal(t, "Your test card is [CARD] and that is all.", text.String())
		assert.Equal(t, stub.cardFrames[0], frames[0], "frames the mask does not touch are byte for byte")
		assert.Equal(t, stub.cardFrames[len(frames)-1], frames[len(frames)-1])
	})

	t.Run("a tool call the policy masks is masked in its input", func(t *testing.T) {
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey,
			"/"+slug+"/model/amazon.nova-lite-v1:0/converse-stream", nativeHeaders(),
			[]byte(`{"messages":[{"role":"user","content":[{"text":"tool-stream"}]}]}`))
		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.NotContains(t, string(raw), regexStreamCardNumber)
		assert.NotContains(t, string(raw), "42424242", "no part of the card number may reach the client")

		frames := readFrames(t, raw)
		require.Len(t, frames, len(stub.toolFrames), "no frame is dropped, only emptied")
		var input strings.Builder
		for i, f := range frames {
			msg, err := eventstream.NewDecoder().Decode(bytes.NewReader(f), nil)
			require.NoError(t, err, "frame %d must be well formed", i)
			var ev struct {
				Delta struct {
					ToolUse *struct {
						Input string `json:"input"`
					} `json:"toolUse"`
				} `json:"delta"`
			}
			if json.Unmarshal(msg.Payload, &ev) == nil && ev.Delta.ToolUse != nil {
				input.WriteString(ev.Delta.ToolUse.Input)
			}
		}
		var call struct {
			Card   string `json:"card"`
			Amount int    `json:"amount"`
		}
		require.NoError(t, json.Unmarshal([]byte(input.String()), &call), "the SDK parses the input: %s", input.String())
		assert.Equal(t, "[CARD]", call.Card)
		assert.Equal(t, 4242, call.Amount, "the number is untouched")
		assert.Equal(t, stub.toolFrames[3], frames[3], "the id and the name of the call are as they came")
		assert.Equal(t, stub.toolFrames[6], frames[6])
		assert.Equal(t, stub.toolFrames[1], frames[1], "the text before the call is as it came")
	})
}

// The LLM store of personal keys is not a native Bedrock route: a native path
// under /store answers as any unknown store route, for a personal key and for no
// key at all, and nothing is relayed to Bedrock.
func TestBedrockNative_StorePathIsNotANativeRoute(t *testing.T) {
	defer Track(t, "BedrockNativeStore")()
	stub := newBedrockRuntimeStub(t)
	up := newJSONUpstream(t, "store-native")
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("store-native")})
	registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("store-native-be"), up.URL()))
	consumerID := CreatePersonalConsumer(t, gatewayID, storeRegistry(registryID, []string{"gpt-4o-mini"}, "gpt-4o-mini"))
	key := createLinkedLLMKey(t, gatewayID, uniqueName("ana"), consumerID)
	status, body := storeChat(t, ProxyURL, gatewayID, key, "gpt-4o-mini")
	require.Equal(t, http.StatusOK, status, body)

	unknownStatus, unknown := gatewayCall(t, ProxyURL, gatewayID, key, http.MethodGet, "/store/v1/zz-unknown", nil)
	require.Equal(t, http.StatusNotFound, unknownStatus)
	for _, path := range []string{
		"/store/model/amazon.nova-lite-v1:0/converse",
		"/store/model/amazon.nova-lite-v1:0/invoke-with-response-stream",
		"/store/model/%2e%2e/converse",
	} {
		for _, k := range []string{key, ""} {
			status, raw := gatewayCall(t, ProxyURL, gatewayID, k, http.MethodPost, path, []byte(bedrockNativeBody))
			assert.Equal(t, http.StatusNotFound, status, "%s: %s", path, raw)
			assert.Equal(t, string(unknown), string(raw), "%s answers as any unknown store route, not as an AWS error", path)
		}
	}
	assert.Equal(t, 1, up.Hits(), "only the chat call reached the upstream")
	assert.Equal(t, 0, stub.callCount(), "nothing was relayed to Bedrock")
}

// A client can make a mask impossible to apply by putting the value where no mask may
// rewrite it. The call goes through, as sent, whatever on_mask_failure a stored
// policy still carries: the setting was removed and is ignored.
func TestBedrockNative_OnMaskFailure(t *testing.T) {
	defer Track(t, "BedrockNativeOnMaskFailure")()
	stub := newBedrockRuntimeStub(t)
	body := `{"messages":[{"role":"user","content":[{"text":"my secret code"}]}],"requestMetadata":{"secret":"x"}}`
	rules := []map[string]any{{"pattern": "secret", "replacement": "[REDACTED]"}}

	t.Run("by default the call goes through unmasked", func(t *testing.T) {
		apiKey, slug := setupBedrockNativeRoute(t, withStages(policyPlugin("regex_replace", map[string]any{
			"target": "request", "rules": rules,
		}), "pre_request"))
		before := stub.callCount()
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey,
			"/"+slug+"/model/amazon.nova-lite-v1:0/converse", nativeHeaders(), []byte(body))
		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Equal(t, before+1, stub.callCount())
		assert.Equal(t, body, string(stub.last(t).Body), "the original, as sent")
	})

	t.Run("a stored on_mask_failure block is ignored and the call goes through unmasked", func(t *testing.T) {
		apiKey, slug := setupBedrockNativeRoute(t, withStages(policyPlugin("regex_replace", map[string]any{
			"target": "request", "rules": rules, "on_mask_failure": "block",
		}), "pre_request"))
		before := stub.callCount()
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey,
			"/"+slug+"/model/amazon.nova-lite-v1:0/converse", nativeHeaders(), []byte(body))
		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Equal(t, before+1, stub.callCount())
		assert.Equal(t, body, string(stub.last(t).Body), "the original, as sent")
	})

	t.Run("a mask that can be applied is applied whatever the setting", func(t *testing.T) {
		apiKey, slug := setupBedrockNativeRoute(t, withStages(policyPlugin("regex_replace", map[string]any{
			"target": "request", "rules": rules, "on_mask_failure": "block",
		}), "pre_request"))
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey,
			"/"+slug+"/model/amazon.nova-lite-v1:0/converse", nativeHeaders(),
			[]byte(`{"messages":[{"role":"user","content":[{"text":"my secret code"}]}]}`))
		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Contains(t, string(stub.last(t).Body), "my [REDACTED] code")
	})

	t.Run("an unknown on_mask_failure value is ignored when the policy is saved", func(t *testing.T) {
		gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("native-mask-setting")})
		status, body := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gatewayID), nil,
			map[string]any{"name": uniqueName("mask"), "slug": "regex_replace", "enabled": true, "mode": "enforce", "stages": []string{"pre_request"},
				"settings": map[string]any{"target": "request", "rules": rules, "on_mask_failure": "explode"}})
		assert.Less(t, status, 300, "body: %v", body)
	})
}

// The real tool_allowlist on a native route: it would strip delete_db from the
// request's toolConfig, which cannot be carried onto the bytes the client sent, so
// the call is refused instead of being forwarded with the tool still in it.
func TestBedrockNative_ToolAllowlistRefusesInsteadOfStripping(t *testing.T) {
	defer Track(t, "BedrockNativeToolAllowlist")()
	stub := newBedrockRuntimeStub(t)
	apiKey, slug := setupBedrockNativeRoute(t,
		withStages(policyPlugin("tool_allowlist", map[string]any{"allow_tools": []string{"search_*"}}), "pre_request"))
	tool := func(name string) string {
		return `{"toolSpec":{"name":"` + name + `","inputSchema":{"json":{"type":"object"}}}}`
	}

	t.Run("a tool outside the allowlist refuses the call", func(t *testing.T) {
		before := stub.callCount()
		body := `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[` + tool("search_docs") + `,` + tool("delete_db") + `]}}`
		status, header, raw := proxyRequest(t, http.MethodPost, apiKey,
			"/"+slug+"/model/amazon.nova-lite-v1:0/converse", nativeHeaders(), []byte(body))
		require.Equal(t, http.StatusForbidden, status, "body: %s", raw)
		assert.Equal(t, "AccessDeniedException", header.Get("X-Amzn-Errortype"))
		assert.Contains(t, string(raw), "AccessDeniedException")
		assert.Equal(t, before, stub.callCount(), "Bedrock was never called")
	})

	t.Run("only allowed tools go through, as sent", func(t *testing.T) {
		body := `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[` + tool("search_docs") + `]}}`
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey,
			"/"+slug+"/model/amazon.nova-lite-v1:0/converse", nativeHeaders(), []byte(body))
		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Equal(t, body, string(stub.last(t).Body))
	})
}
