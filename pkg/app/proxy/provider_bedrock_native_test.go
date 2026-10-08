// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy_test

import (
	"bytes"
	"context"
	"errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/bedrocknative"
	"iter"
	"net/http"
	"sync"
	"testing"
	"time"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	factorymocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory/mocks"
	providermocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/mocks"
	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nativeStubClient is a provider client that also relays native Bedrock calls.
// It embeds the generated mock, which fails the test on any translated call:
// the native branch must never reach Completions or CompletionsStream.
type nativeStubClient struct {
	*providermocks.Client
	mu     sync.Mutex
	calls  []nativeCall
	answer func(req providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error)
}

type nativeCall struct {
	cfg *providers.Config
	req providers.NativeBedrockRequest
}

func (c *nativeStubClient) InvokeNative(
	_ context.Context,
	cfg *providers.Config,
	req providers.NativeBedrockRequest,
) (*providers.NativeBedrockResponse, error) {
	c.mu.Lock()
	c.calls = append(c.calls, nativeCall{cfg: cfg, req: req})
	c.mu.Unlock()
	return c.answer(req)
}

func newNativeInvoker(t *testing.T, answer func(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error)) (appproxy.ProviderInvoker, *nativeStubClient) {
	t.Helper()
	client := &nativeStubClient{Client: providermocks.NewClient(t), answer: answer}
	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("bedrock").Return(client, nil).Maybe()
	return appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger()), client
}

func nativeRequest(op, rawModelID, modelID string, body string) *infracontext.RequestContext {
	return &infracontext.RequestContext{
		Body:         []byte(body),
		SourceFormat: "bedrock_native",
		Headers: map[string][]string{
			"Content-Type":  {"application/json"},
			"Authorization": {"AWS4-HMAC-SHA256 Credential=CLIENT/x"},
		},
		BedrockNative: &infracontext.BedrockNativeTarget{Op: bedrocknative.Op(op), RawModelID: rawModelID, ModelID: modelID},
	}
}

func TestProviderInvoke_NativeBedrock_ConverseRelaysBytesAndReadsUsage(t *testing.T) {
	const answer = `{"output":{"message":{"role":"assistant","content":[{"text":"ok"}]}},"stopReason":"end_turn","usage":{"inputTokens":7,"outputTokens":3,"totalTokens":10}}`
	inv, client := newNativeInvoker(t, func(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error) {
		return &providers.NativeBedrockResponse{
			StatusCode: http.StatusOK,
			Headers:    http.Header{"Content-Type": {"application/json"}, "X-Amzn-Requestid": {"r-1"}},
			Body:       []byte(answer),
		}, nil
	})
	// Spacing and key order that any re-serialiser would normalise away.
	body := "{ \"messages\" : [ {\"role\":\"user\", \"content\":[{\"text\":\"hi\"}]} ],  \"zz\":1 }"
	req := nativeRequest("converse", "amazon.nova-lite-v1%3A0", "amazon.nova-lite-v1:0", body)

	resp, err := inv.Invoke(context.Background(), apiKeyTarget("bedrock"), req)
	require.NoError(t, err)

	require.Len(t, client.calls, 1)
	call := client.calls[0]
	assert.Equal(t, body, string(call.req.Body), "the body must reach the client untouched")
	assert.Equal(t, "/model/amazon.nova-lite-v1:0/converse", call.req.Path)
	assert.Equal(t, "/model/amazon.nova-lite-v1%3A0/converse", call.req.RawPath)
	assert.False(t, call.req.Stream)
	assert.Equal(t, "AWS4-HMAC-SHA256 Credential=CLIENT/x", call.req.Headers.Get("Authorization"),
		"the invoker hands the headers over; the client's allow-list is what drops them")
	assert.Equal(t, "secret", call.cfg.Credentials.ApiKey, "the registry's credentials are used, never the caller's Authorization")

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, answer, string(resp.Body))
	assert.Equal(t, "amazon.nova-lite-v1:0", resp.SentModel)
	assert.Equal(t, []string{"bedrock"}, resp.Headers["X-Selected-Provider"])
	assert.Equal(t, []string{"amazon.nova-lite-v1:0"}, resp.Headers["X-Selected-Model"])
	assert.Equal(t, []string{"r-1"}, resp.Headers["X-Amzn-Requestid"])
	assert.Equal(t, "stop", resp.FinishReason)
	require.NotNil(t, resp.Usage)
	assert.Equal(t, 7, resp.Usage.InputTokens)
	assert.Equal(t, 3, resp.Usage.OutputTokens)

	metaUsage, ok := req.Metadata[adapter.MetadataUsageKey].(*adapter.CanonicalUsage)
	require.True(t, ok, "usage must be written to the request metadata for the token budget")
	assert.Equal(t, 7, metaUsage.InputTokens)
	assert.Equal(t, "bedrock", req.Provider)
	assert.Equal(t, "bedrock_native", req.SourceFormat)
}

func TestProviderInvoke_NativeBedrock_InvokeReadsUsageFromHeaders(t *testing.T) {
	// Mistral's prompt-style body carries no token counts: only the headers do.
	inv, _ := newNativeInvoker(t, func(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error) {
		return &providers.NativeBedrockResponse{
			StatusCode: http.StatusOK,
			Headers: http.Header{
				"Content-Type":                      {"application/json"},
				"X-Amzn-Bedrock-Input-Token-Count":  {"21"},
				"X-Amzn-Bedrock-Output-Token-Count": {"9"},
			},
			Body: []byte(`{"outputs":[{"text":"Bonjour","stop_reason":"stop"}]}`),
		}, nil
	})
	req := nativeRequest("invoke", "mistral.mistral-7b-instruct-v0:2", "mistral.mistral-7b-instruct-v0:2", `{"prompt":"hi"}`)

	resp, err := inv.Invoke(context.Background(), apiKeyTarget("bedrock"), req)
	require.NoError(t, err)
	require.NotNil(t, resp.Usage)
	assert.Equal(t, 21, resp.Usage.InputTokens)
	assert.Equal(t, 9, resp.Usage.OutputTokens)
	assert.Equal(t, "stop", resp.FinishReason)
	assert.Equal(t, []string{"21"}, resp.Headers["X-Amzn-Bedrock-Input-Token-Count"], "the accounting headers are relayed")
	assert.Equal(t, 21, req.Metadata[adapter.MetadataUsageKey].(*adapter.CanonicalUsage).InputTokens)
}

func TestProviderInvoke_NativeBedrock_AWSErrorIsAResponseNotAnError(t *testing.T) {
	const awsBody = `{"message":"Malformed input request"}`
	inv, _ := newNativeInvoker(t, func(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error) {
		return &providers.NativeBedrockResponse{
			StatusCode: http.StatusBadRequest,
			Headers:    http.Header{"X-Amzn-Errortype": {"ValidationException"}, "Content-Type": {"application/json"}},
			Body:       []byte(awsBody),
		}, nil
	})
	req := nativeRequest("converse", "m", "m", `{}`)

	resp, err := inv.Invoke(context.Background(), apiKeyTarget("bedrock"), req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, awsBody, string(resp.Body))
	assert.Equal(t, []string{"ValidationException"}, resp.Headers["X-Amzn-Errortype"])
	assert.Nil(t, resp.Usage)
	assert.NotContains(t, req.Metadata, adapter.MetadataUsageKey)
}

func TestProviderInvoke_NativeBedrock_Guards(t *testing.T) {
	t.Run("a registry of another provider is refused", func(t *testing.T) {
		client := providermocks.NewClient(t)
		locator := factorymocks.NewProviderLocator(t)
		locator.EXPECT().Get("openai").Return(client, nil).Maybe()
		inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

		_, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), nativeRequest("converse", "m", "m", `{}`))
		assert.ErrorIs(t, err, routingdomain.ErrNoRegistryServesModel)
	})

	t.Run("a passthrough registry never adopts the caller's SigV4 header as a credential", func(t *testing.T) {
		inv, client := newNativeInvoker(t, func(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error) {
			return &providers.NativeBedrockResponse{StatusCode: http.StatusOK, Body: []byte(`{}`)}, nil
		})
		target := apiKeyTarget("bedrock")
		target.LLMTarget.Auth = &registrydomain.TargetAuth{Type: registrydomain.AuthTypePassthrough}

		_, err := inv.Invoke(context.Background(), target, nativeRequest("converse", "m", "m", `{}`))
		require.NoError(t, err)
		require.Len(t, client.calls, 1)
		assert.Empty(t, client.calls[0].cfg.Credentials.ApiKey)
	})

	t.Run("the allow-list is enforced read-only", func(t *testing.T) {
		inv, client := newNativeInvoker(t, func(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error) {
			return nil, errors.New("must not be called")
		})
		req := nativeRequest("converse", "m", "other.model-v1:0", `{}`)
		req.AllowedModels = []string{"amazon.nova-*"}

		_, err := inv.Invoke(context.Background(), apiKeyTarget("bedrock"), req)
		assert.ErrorIs(t, err, appproxy.ErrModelNotAllowed)
		assert.Empty(t, client.calls)
	})

	t.Run("an allowed model passes", func(t *testing.T) {
		inv, client := newNativeInvoker(t, func(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error) {
			return &providers.NativeBedrockResponse{StatusCode: http.StatusOK, Body: []byte(`{}`)}, nil
		})
		req := nativeRequest("converse", "amazon.nova-lite-v1:0", "amazon.nova-lite-v1:0", `{}`)
		req.AllowedModels = []string{"amazon.nova-*"}

		_, err := inv.Invoke(context.Background(), apiKeyTarget("bedrock"), req)
		require.NoError(t, err)
		assert.Len(t, client.calls, 1)
	})

	t.Run("a client without native support is a capability error", func(t *testing.T) {
		client := providermocks.NewClient(t)
		locator := factorymocks.NewProviderLocator(t)
		locator.EXPECT().Get("bedrock").Return(client, nil).Once()
		inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())

		_, err := inv.Invoke(context.Background(), apiKeyTarget("bedrock"), nativeRequest("converse", "m", "m", `{}`))
		assert.ErrorIs(t, err, appproxy.ErrCapabilityNotSupported)
	})

	t.Run("a transport failure is an error the forwarder can fail over on", func(t *testing.T) {
		inv, _ := newNativeInvoker(t, func(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error) {
			return nil, errors.New("connection reset")
		})
		resp, err := inv.Invoke(context.Background(), apiKeyTarget("bedrock"), nativeRequest("invoke", "m", "m", `{}`))
		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "connection reset")
	})
}

// nativeEvent encodes one ConverseStream event frame with the SDK encoder, so
// the fixtures are what the wire carries and not what this package builds.
func nativeEvent(t *testing.T, eventType, payload string) []byte {
	t.Helper()
	var headers eventstream.Headers
	headers.Set(":message-type", eventstream.StringValue("event"))
	headers.Set(":event-type", eventstream.StringValue(eventType))
	headers.Set(":content-type", eventstream.StringValue("application/json"))
	var buf bytes.Buffer
	require.NoError(t, eventstream.NewEncoder().Encode(&buf, eventstream.Message{Headers: headers, Payload: []byte(payload)}))
	return buf.Bytes()
}

func nativeFrameSeq(frames ...[]byte) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for _, f := range frames {
			if !yield(f, nil) {
				return
			}
		}
	}
}

func TestProviderInvokeStream_NativeBedrock_RelaysFramesAndObservesTheView(t *testing.T) {
	frames := [][]byte{
		nativeEvent(t, "contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":"Hello"}}`),
		nativeEvent(t, "messageStop", `{"stopReason":"end_turn"}`),
		nativeEvent(t, "metadata", `{"usage":{"inputTokens":9,"outputTokens":4,"totalTokens":13}}`),
	}
	inv, client := newNativeInvoker(t, func(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error) {
		return &providers.NativeBedrockResponse{
			StatusCode: http.StatusOK,
			Headers:    http.Header{"Content-Type": {"application/vnd.amazon.eventstream"}},
			Frames:     nativeFrameSeq(frames...),
		}, nil
	})
	req := nativeRequest("converse-stream", "amazon.nova-lite-v1%3A0", "amazon.nova-lite-v1:0", `{"messages":[]}`)

	resp, err := inv.InvokeStream(context.Background(), apiKeyTarget("bedrock"), req)
	require.NoError(t, err)
	require.NotNil(t, resp.Stream)
	assert.True(t, resp.RawFrames)
	require.NotNil(t, resp.StreamView)
	assert.Equal(t, []string{"application/vnd.amazon.eventstream"}, resp.Headers["Content-Type"])
	require.Len(t, client.calls, 1)
	assert.True(t, client.calls[0].req.Stream)
	assert.Equal(t, "/model/amazon.nova-lite-v1:0/converse-stream", client.calls[0].req.Path)

	var got [][]byte
	for frame, ferr := range resp.Stream {
		require.NoError(t, ferr)
		got = append(got, frame)
	}
	assert.Equal(t, frames, got, "every frame must be relayed identical")

	usage, ok := req.Metadata[adapter.MetadataUsageKey].(*adapter.CanonicalUsage)
	require.True(t, ok, "the stream observer must record usage from the decoded view")
	assert.Equal(t, 9, usage.InputTokens)
	assert.Equal(t, 4, usage.OutputTokens)
}

func TestProviderInvokeStream_NativeBedrock_ErrorBeforeTheStreamIsAResponse(t *testing.T) {
	const awsBody = `{"message":"too many requests"}`
	inv, _ := newNativeInvoker(t, func(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error) {
		return &providers.NativeBedrockResponse{
			StatusCode: http.StatusTooManyRequests,
			Headers:    http.Header{"X-Amzn-Errortype": {"ThrottlingException"}},
			Body:       []byte(awsBody),
		}, nil
	})
	resp, err := inv.InvokeStream(context.Background(), apiKeyTarget("bedrock"),
		nativeRequest("converse-stream", "m", "m", `{}`))
	require.NoError(t, err)
	assert.Nil(t, resp.Stream)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.Equal(t, awsBody, string(resp.Body))
}

func TestProviderInvokeStream_NativeBedrock_ReportsAMidStreamFailure(t *testing.T) {
	boom := errors.New("connection reset by peer")
	inv, _ := newNativeInvoker(t, func(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error) {
		return &providers.NativeBedrockResponse{
			StatusCode: http.StatusOK,
			Frames: func(yield func([]byte, error) bool) {
				if !yield(nativeEvent(t, "messageStart", `{"role":"assistant"}`), nil) {
					return
				}
				yield(nil, boom)
			},
		}, nil
	})
	resp, err := inv.InvokeStream(context.Background(), apiKeyTarget("bedrock"),
		nativeRequest("invoke-with-response-stream", "m", "m", `{}`))
	require.NoError(t, err)

	var n int
	var streamErr error
	for _, ferr := range resp.Stream {
		if ferr != nil {
			streamErr = ferr
			break
		}
		n++
	}
	assert.Equal(t, 1, n)
	assert.ErrorIs(t, streamErr, boom)
}

func TestProviderInvokeStream_NativeBedrock_StopsTheUpstreamWhenTheConsumerDoes(t *testing.T) {
	var closed bool
	inv, _ := newNativeInvoker(t, func(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error) {
		return &providers.NativeBedrockResponse{
			StatusCode: http.StatusOK,
			Frames: func(yield func([]byte, error) bool) {
				defer func() { closed = true }()
				for {
					if !yield(nativeEvent(t, "messageStart", `{"role":"assistant"}`), nil) {
						return
					}
				}
			},
		}, nil
	})
	resp, err := inv.InvokeStream(context.Background(), apiKeyTarget("bedrock"),
		nativeRequest("converse-stream", "m", "m", `{}`))
	require.NoError(t, err)
	for range resp.Stream {
		break
	}
	assert.True(t, closed, "breaking out of the stream must release the upstream sequence")
}

func TestProviderInvoke_NativeBedrock_InvokeUsageKeepsTheCacheBuckets(t *testing.T) {
	inv, _ := newNativeInvoker(t, func(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error) {
		return &providers.NativeBedrockResponse{
			StatusCode: http.StatusOK,
			Headers: http.Header{
				"X-Amzn-Bedrock-Input-Token-Count":             {"10"},
				"X-Amzn-Bedrock-Output-Token-Count":            {"5"},
				"X-Amzn-Bedrock-Cache-Read-Input-Token-Count":  {"100"},
				"X-Amzn-Bedrock-Cache-Write-Input-Token-Count": {"20"},
			},
			Body: []byte(`{"type":"message","role":"assistant","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":10,"output_tokens":7}}`),
		}, nil
	})
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("bedrock"),
		nativeRequest("invoke", "m", "m", `{"anthropic_version":"v","messages":[]}`))
	require.NoError(t, err)
	require.NotNil(t, resp.Usage)
	assert.Equal(t, 100, resp.Usage.CachedInputTokens)
	assert.Equal(t, 20, resp.Usage.CacheWriteInputTokens)
	assert.Equal(t, 130, resp.Usage.InputTokens)
	assert.Equal(t, 7, resp.Usage.OutputTokens, "the body may report more than the headers do")
}

// Usage belongs to one attempt: a failover that lands on an AWS error, or on a
// stream, must not carry what the attempt before it reported.
func TestProviderInvoke_NativeBedrock_UsageIsResetPerAttempt(t *testing.T) {
	stale := &adapter.CanonicalUsage{InputTokens: 999, OutputTokens: 999, TotalTokens: 1998}

	t.Run("an error answer clears it", func(t *testing.T) {
		inv, _ := newNativeInvoker(t, func(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error) {
			return &providers.NativeBedrockResponse{StatusCode: http.StatusServiceUnavailable, Body: []byte(`{"message":"down"}`)}, nil
		})
		req := nativeRequest("converse", "m", "m", `{}`)
		req.Metadata = map[string]interface{}{adapter.MetadataUsageKey: stale}
		_, err := inv.Invoke(context.Background(), apiKeyTarget("bedrock"), req)
		require.NoError(t, err)
		assert.NotContains(t, req.Metadata, adapter.MetadataUsageKey)
	})

	t.Run("a transport failure clears it", func(t *testing.T) {
		inv, _ := newNativeInvoker(t, func(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error) {
			return nil, errors.New("reset")
		})
		req := nativeRequest("invoke", "m", "m", `{}`)
		req.Metadata = map[string]interface{}{adapter.MetadataUsageKey: stale}
		_, err := inv.Invoke(context.Background(), apiKeyTarget("bedrock"), req)
		require.Error(t, err)
		assert.NotContains(t, req.Metadata, adapter.MetadataUsageKey)
	})

	t.Run("a stream does not merge into it", func(t *testing.T) {
		inv, _ := newNativeInvoker(t, func(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error) {
			return &providers.NativeBedrockResponse{
				StatusCode: http.StatusOK,
				Frames:     nativeFrameSeq(nativeEvent(t, "metadata", `{"usage":{"inputTokens":3,"outputTokens":4,"totalTokens":7}}`)),
			}, nil
		})
		req := nativeRequest("converse-stream", "m", "m", `{}`)
		req.Metadata = map[string]interface{}{adapter.MetadataUsageKey: stale}
		resp, err := inv.InvokeStream(context.Background(), apiKeyTarget("bedrock"), req)
		require.NoError(t, err)
		for range resp.Stream {
		}
		got := req.Metadata[adapter.MetadataUsageKey].(*adapter.CanonicalUsage)
		require.NotNil(t, got)
		assert.Equal(t, 3, got.InputTokens, "the max-merge would have kept the stale 999")
	})
}

// stubModels is the opaque-ARN lookup: it answers from a map, and from `late`
// only from the second call on, which is a lookup that lands while the call runs.
type stubModels struct {
	known map[string]string
	late  map[string]string
	// lateAfter is how many lookups miss before late answers; 1 when unset.
	lateAfter int
	calls     map[string]int
	// resolve, when set, answers the blocking Resolve the forwarder makes.
	resolve func(ctx context.Context, arn string, wait time.Duration) (string, bool)
}

func (m *stubModels) Lookup(_ context.Context, _ *registrydomain.Registry, arn string) (string, bool) {
	if m.calls == nil {
		m.calls = map[string]int{}
	}
	m.calls[arn]++
	if id, ok := m.known[arn]; ok {
		return id, true
	}
	after := m.lateAfter
	if after == 0 {
		after = 1
	}
	if id, ok := m.late[arn]; ok && m.calls[arn] > after {
		return id, true
	}
	return "", false
}

func (m *stubModels) Resolve(ctx context.Context, reg *registrydomain.Registry, arn string, wait time.Duration) (string, bool) {
	if m.resolve != nil {
		return m.resolve(ctx, arn, wait)
	}
	return m.Lookup(ctx, reg, arn)
}

func (m *stubModels) Close(context.Context) error { return nil }

func newNativeInvokerWithModels(t *testing.T, models appcatalog.BedrockModelResolver, answer func(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error)) appproxy.ProviderInvoker {
	t.Helper()
	client := &nativeStubClient{Client: providermocks.NewClient(t), answer: answer}
	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("bedrock").Return(client, nil).Maybe()
	return appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger(), appproxy.WithBedrockModelResolver(models))
}

const (
	nativeARNBase   = "anthropic.claude-sonnet-4-5-20250929-v1:0"
	nativeSystemARN = "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us." + nativeARNBase
	nativeAppARN    = "arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/abc123xyz"
	nativeOKAnswer  = `{"output":{"message":{"role":"assistant","content":[{"text":"ok"}]}},"stopReason":"end_turn","usage":{"inputTokens":1,"outputTokens":1,"totalTokens":2}}`
)

func okAnswer(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error) {
	return &providers.NativeBedrockResponse{StatusCode: http.StatusOK, Body: []byte(nativeOKAnswer)}, nil
}

// The span names the model that served the call, which a client that sent an
// ARN never named; SentModel keeps what was sent.
func TestProviderInvoke_NativeBedrock_SpanModelIsTheResolvedModel(t *testing.T) {
	cases := []struct {
		name         string
		modelID      string
		models       *stubModels
		wantModel    string
		wantResolved string
	}{
		{"plain id", "amazon.nova-lite-v1:0", &stubModels{}, "amazon.nova-lite-v1:0", ""},
		{"system profile ARN carries the profile id", nativeSystemARN, &stubModels{}, "us." + nativeARNBase, "us." + nativeARNBase},
		{"application profile resolved earlier", nativeAppARN, &stubModels{known: map[string]string{nativeAppARN: nativeARNBase}}, nativeARNBase, nativeARNBase},
		{"application profile resolved while the call ran", nativeAppARN, &stubModels{late: map[string]string{nativeAppARN: nativeARNBase}}, nativeARNBase, nativeARNBase},
		{"application profile not resolved falls back to the path id", nativeAppARN, &stubModels{}, nativeAppARN, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inv := newNativeInvokerWithModels(t, tc.models, okAnswer)
			req := nativeRequest("converse", tc.modelID, tc.modelID, `{}`)
			resp, err := inv.Invoke(context.Background(), apiKeyTarget("bedrock"), req)
			require.NoError(t, err)
			assert.Equal(t, tc.wantModel, resp.Model)
			assert.Equal(t, tc.wantResolved, req.ResolvedModel)
			assert.Equal(t, tc.modelID, resp.SentModel, "what was sent stays literal")
			assert.Equal(t, tc.modelID, req.BedrockNative.ModelID)
		})
	}
}

func TestProviderInvoke_NativeBedrock_ErrorAnswerStillCarriesTheModel(t *testing.T) {
	inv := newNativeInvokerWithModels(t, &stubModels{known: map[string]string{nativeAppARN: nativeARNBase}},
		func(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error) {
			return &providers.NativeBedrockResponse{StatusCode: http.StatusServiceUnavailable, Body: []byte(`{"message":"down"}`)}, nil
		})
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("bedrock"), nativeRequest("converse", nativeAppARN, nativeAppARN, `{}`))
	require.NoError(t, err)
	assert.Equal(t, nativeARNBase, resp.Model)
}

// A stream outlives the lookup the call started, so the model is read again when
// it ends and written to the span.
func TestProviderInvokeStream_NativeBedrock_ModelIsNotWrittenFromTheStream(t *testing.T) {
	// The invoker only reads the model before the call and right after it. A late
	// answer is the forwarder's to read at the end of the stream, on the goroutine
	// that ends it (TestForwarder_NativeStreamReadsTheModelAtItsEnd), because a
	// write from the stream's own goroutine races with a cut stream's drain.
	models := &stubModels{late: map[string]string{nativeAppARN: nativeARNBase}, lateAfter: 2}
	inv := newNativeInvokerWithModels(t, models, func(providers.NativeBedrockRequest) (*providers.NativeBedrockResponse, error) {
		return &providers.NativeBedrockResponse{StatusCode: http.StatusOK, Frames: nativeFrameSeq(nativeEvent(t, "messageStart", `{"role":"assistant"}`))}, nil
	})
	req := nativeRequest("converse-stream", nativeAppARN, nativeAppARN, `{}`)

	resp, err := inv.InvokeStream(context.Background(), apiKeyTarget("bedrock"), req)
	require.NoError(t, err)
	assert.Equal(t, nativeAppARN, resp.Model, "not known when the stream starts")
	for range resp.Stream {
	}
	assert.Empty(t, req.ResolvedModel, "the stream does not write the request")
}
