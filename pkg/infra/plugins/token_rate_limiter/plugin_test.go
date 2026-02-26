package token_rate_limiter_test

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/token_rate_limiter"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setup(t *testing.T) (*token_rate_limiter.TokenRateLimiterPlugin, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	p := token_rate_limiter.NewTokenRateLimiterPlugin(logrus.New(), rc).(*token_rate_limiter.TokenRateLimiterPlugin)
	return p, mr
}

func defaultSettings() map[string]interface{} {
	return map[string]interface{}{
		"window": map[string]interface{}{
			"unit": "minute",
			"max":  100,
		},
	}
}

func pluginCfg(settings map[string]interface{}) pluginTypes.PluginConfig {
	return pluginTypes.PluginConfig{
		ID:       "test-plugin",
		Name:     "token_rate_limiter",
		Enabled:  true,
		Stage:    pluginTypes.PreRequest,
		Settings: settings,
	}
}

func newEvtCtx() *metrics.EventContext {
	return metrics.NewEventContext("", "", nil)
}

// ---------------------------------------------------------------------------
// Constructor & metadata
// ---------------------------------------------------------------------------

func TestNewPlugin(t *testing.T) {
	p, _ := setup(t)
	assert.NotNil(t, p)
	assert.Implements(t, (*pluginiface.Plugin)(nil), p)
}

func TestName(t *testing.T) {
	p, _ := setup(t)
	assert.Equal(t, "token_rate_limiter", p.Name())
}

func TestStages(t *testing.T) {
	p, _ := setup(t)
	stages := p.Stages()
	assert.Contains(t, stages, pluginTypes.PreRequest)
	assert.Contains(t, stages, pluginTypes.PostResponse)
}

// ---------------------------------------------------------------------------
// ValidateConfig
// ---------------------------------------------------------------------------

func TestValidateConfig_Valid(t *testing.T) {
	p, _ := setup(t)
	assert.NoError(t, p.ValidateConfig(pluginCfg(defaultSettings())))
}

func TestValidateConfig_NilSettings(t *testing.T) {
	p, _ := setup(t)
	err := p.ValidateConfig(pluginTypes.PluginConfig{Settings: nil})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires settings")
}

func TestValidateConfig_InvalidUnit(t *testing.T) {
	p, _ := setup(t)
	s := map[string]interface{}{
		"window": map[string]interface{}{"unit": "week", "max": 10},
	}
	assert.Error(t, p.ValidateConfig(pluginCfg(s)))
}

func TestValidateConfig_ZeroMax(t *testing.T) {
	p, _ := setup(t)
	s := map[string]interface{}{
		"window": map[string]interface{}{"unit": "minute", "max": 0},
	}
	assert.Error(t, p.ValidateConfig(pluginCfg(s)))
}

func TestValidateConfig_AllUnits(t *testing.T) {
	p, _ := setup(t)
	for _, unit := range []string{"second", "minute", "hour", "day"} {
		s := map[string]interface{}{
			"window": map[string]interface{}{"unit": unit, "max": 50},
		}
		assert.NoError(t, p.ValidateConfig(pluginCfg(s)), "unit=%s should be valid", unit)
	}
}

// ---------------------------------------------------------------------------
// Execute — skip when no provider
// ---------------------------------------------------------------------------

func TestExecute_NoProvider_Skips(t *testing.T) {
	p, _ := setup(t)
	req := &types.RequestContext{
		Provider: "",
		Stage:    pluginTypes.PreRequest,
		Headers:  map[string][]string{},
	}
	resp, err := p.Execute(context.Background(), pluginCfg(defaultSettings()), req, &types.ResponseContext{}, newEvtCtx())
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// PreRequest stage
// ---------------------------------------------------------------------------

func TestPreRequest_AllowsWhenUnderLimit(t *testing.T) {
	p, _ := setup(t)
	req := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PreRequest,
		Headers:  map[string][]string{},
		IP:       "10.0.0.1",
	}
	resp, err := p.Execute(context.Background(), pluginCfg(defaultSettings()), req, &types.ResponseContext{}, newEvtCtx())
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "100", resp.Headers["X-Ratelimit-Limit-Tokens"][0])
	assert.Equal(t, "100", resp.Headers["X-Ratelimit-Remaining-Tokens"][0])
}

func TestPreRequest_RejectsWhenOverLimit(t *testing.T) {
	p, mr := setup(t)

	counterKey := "trl:test-plugin:10.0.0.1"
	require.NoError(t, mr.Set(counterKey, "100"))
	mr.SetTTL(counterKey, 30_000_000_000) // 30s

	req := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PreRequest,
		Headers:  map[string][]string{},
		IP:       "10.0.0.1",
	}
	resp, err := p.Execute(context.Background(), pluginCfg(defaultSettings()), req, &types.ResponseContext{}, newEvtCtx())
	assert.Nil(t, resp)
	require.Error(t, err)

	var pluginErr *pluginTypes.PluginError
	require.True(t, errors.As(err, &pluginErr))
	assert.Equal(t, http.StatusTooManyRequests, pluginErr.StatusCode)
	assert.Contains(t, pluginErr.Message, "Token rate limit exceeded")
	assert.Equal(t, "0", pluginErr.Headers["X-Ratelimit-Remaining-Tokens"][0])
}

func TestPreRequest_RejectsWhenExactlyAtLimit(t *testing.T) {
	p, mr := setup(t)

	settings := map[string]interface{}{
		"window": map[string]interface{}{"unit": "minute", "max": 50},
	}
	counterKey := "trl:test-plugin:10.0.0.1"
	require.NoError(t, mr.Set(counterKey, "50"))
	mr.SetTTL(counterKey, 30_000_000_000)

	req := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PreRequest,
		Headers:  map[string][]string{},
		IP:       "10.0.0.1",
	}
	resp, err := p.Execute(context.Background(), pluginCfg(settings), req, &types.ResponseContext{}, newEvtCtx())
	assert.Nil(t, resp)
	require.Error(t, err)

	var pluginErr *pluginTypes.PluginError
	require.True(t, errors.As(err, &pluginErr))
	assert.Equal(t, http.StatusTooManyRequests, pluginErr.StatusCode)
}

func TestPreRequest_AllowsJustUnderLimit(t *testing.T) {
	p, mr := setup(t)

	settings := map[string]interface{}{
		"window": map[string]interface{}{"unit": "minute", "max": 50},
	}
	counterKey := "trl:test-plugin:10.0.0.1"
	require.NoError(t, mr.Set(counterKey, "49"))
	mr.SetTTL(counterKey, 30_000_000_000)

	req := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PreRequest,
		Headers:  map[string][]string{},
		IP:       "10.0.0.1",
	}
	resp, err := p.Execute(context.Background(), pluginCfg(settings), req, &types.ResponseContext{}, newEvtCtx())
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "1", resp.Headers["X-Ratelimit-Remaining-Tokens"][0])
}

// ---------------------------------------------------------------------------
// PostResponse stage — non-streaming
// ---------------------------------------------------------------------------

func TestPostResponse_RecordsTokens_OpenAI(t *testing.T) {
	p, mr := setup(t)

	openaiResponse := `{
		"id": "chatcmpl-123",
		"object": "chat.completion",
		"model": "gpt-4",
		"choices": [{"message": {"role": "assistant", "content": "Hello!"}, "finish_reason": "stop", "index": 0}],
		"usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
	}`

	req := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PostResponse,
		Headers:  map[string][]string{},
		IP:       "10.0.0.1",
	}
	resp := &types.ResponseContext{
		Body:      []byte(openaiResponse),
		Streaming: false,
	}

	result, err := p.Execute(context.Background(), pluginCfg(defaultSettings()), req, resp, newEvtCtx())
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "30", result.Headers["X-Tokens-Consumed"][0])
	assert.Equal(t, "70", result.Headers["X-Ratelimit-Remaining-Tokens"][0])

	val, err := mr.Get("trl:test-plugin:10.0.0.1")
	require.NoError(t, err)
	assert.Equal(t, "30", val)

	assert.True(t, mr.Exists("trl:test-plugin:10.0.0.1"))
	ttl := mr.TTL("trl:test-plugin:10.0.0.1")
	assert.True(t, ttl > 0, "key should have a TTL")
}

func TestPostResponse_AccumulatesAcrossRequests(t *testing.T) {
	p, mr := setup(t)

	openaiResponse := func(total int) []byte {
		return []byte(`{
			"id": "chatcmpl-123",
			"object": "chat.completion",
			"model": "gpt-4",
			"choices": [{"message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop", "index": 0}],
			"usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": ` + itoa(total) + `}
		}`)
	}

	cfg := pluginCfg(defaultSettings())
	req := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PostResponse,
		Headers:  map[string][]string{},
		IP:       "10.0.0.1",
	}

	_, err := p.Execute(context.Background(), cfg, req, &types.ResponseContext{Body: openaiResponse(40)}, newEvtCtx())
	require.NoError(t, err)

	_, err = p.Execute(context.Background(), cfg, req, &types.ResponseContext{Body: openaiResponse(35)}, newEvtCtx())
	require.NoError(t, err)

	val, _ := mr.Get("trl:test-plugin:10.0.0.1")
	assert.Equal(t, "75", val)
}

func TestPostResponse_EmptyBody_Skips(t *testing.T) {
	p, _ := setup(t)
	req := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PostResponse,
		Headers:  map[string][]string{},
		IP:       "10.0.0.1",
	}
	resp, err := p.Execute(context.Background(), pluginCfg(defaultSettings()), req, &types.ResponseContext{Body: nil}, newEvtCtx())
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestPostResponse_NoUsage_Skips(t *testing.T) {
	p, mr := setup(t)

	body := `{
		"id": "chatcmpl-123",
		"object": "chat.completion",
		"model": "gpt-4",
		"choices": [{"message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop", "index": 0}]
	}`

	req := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PostResponse,
		Headers:  map[string][]string{},
		IP:       "10.0.0.1",
	}
	resp, err := p.Execute(context.Background(), pluginCfg(defaultSettings()), req, &types.ResponseContext{Body: []byte(body)}, newEvtCtx())
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.False(t, mr.Exists("trl:test-plugin:10.0.0.1"), "no key should be created when usage is zero")
}

// ---------------------------------------------------------------------------
// PostResponse stage — streaming
// ---------------------------------------------------------------------------

func TestPostResponse_Streaming_ExtractsUsage(t *testing.T) {
	p, mr := setup(t)

	streamBody := `{"id":"chatcmpl-1","choices":[{"delta":{"content":"Hel"},"index":0}]}
{"id":"chatcmpl-1","choices":[{"delta":{"content":"lo"},"index":0}]}
{"id":"chatcmpl-1","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":15,"total_tokens":25}}`

	req := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PostResponse,
		Headers:  map[string][]string{},
		IP:       "10.0.0.1",
	}
	resp := &types.ResponseContext{
		Body:      []byte(streamBody),
		Streaming: true,
	}

	result, err := p.Execute(context.Background(), pluginCfg(defaultSettings()), req, resp, newEvtCtx())
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "25", result.Headers["X-Tokens-Consumed"][0])

	val, _ := mr.Get("trl:test-plugin:10.0.0.1")
	assert.Equal(t, "25", val)
}

func TestPostResponse_Streaming_NoUsageChunk_Skips(t *testing.T) {
	p, mr := setup(t)

	streamBody := `{"id":"chatcmpl-1","choices":[{"delta":{"content":"Hello"},"index":0}]}
{"id":"chatcmpl-1","choices":[{"delta":{},"finish_reason":"stop","index":0}]}`

	req := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PostResponse,
		Headers:  map[string][]string{},
		IP:       "10.0.0.1",
	}
	resp := &types.ResponseContext{
		Body:      []byte(streamBody),
		Streaming: true,
	}

	result, err := p.Execute(context.Background(), pluginCfg(defaultSettings()), req, resp, newEvtCtx())
	require.NoError(t, err)
	require.NotNil(t, resp)
	_ = result

	assert.False(t, mr.Exists("trl:test-plugin:10.0.0.1"))
}

// ---------------------------------------------------------------------------
// Identifier extraction
// ---------------------------------------------------------------------------

func TestIdentifier_CustomHeader(t *testing.T) {
	p, mr := setup(t)

	settings := map[string]interface{}{
		"identifier_header": "X-API-Key",
		"window":            map[string]interface{}{"unit": "minute", "max": 100},
	}

	require.NoError(t, mr.Set("trl:test-plugin:my-api-key-123", "99"))
	mr.SetTTL("trl:test-plugin:my-api-key-123", 30_000_000_000)

	req := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PreRequest,
		Headers:  map[string][]string{"X-API-Key": {"my-api-key-123"}},
		IP:       "10.0.0.1",
	}
	resp, err := p.Execute(context.Background(), pluginCfg(settings), req, &types.ResponseContext{}, newEvtCtx())
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "1", resp.Headers["X-Ratelimit-Remaining-Tokens"][0])
}

func TestIdentifier_CustomHeaderCaseInsensitive(t *testing.T) {
	p, _ := setup(t)

	settings := map[string]interface{}{
		"identifier_header": "x-api-key",
		"window":            map[string]interface{}{"unit": "minute", "max": 100},
	}

	req := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PreRequest,
		Headers:  map[string][]string{"X-Api-Key": {"key-456"}},
		IP:       "10.0.0.1",
	}
	resp, err := p.Execute(context.Background(), pluginCfg(settings), req, &types.ResponseContext{}, newEvtCtx())
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "100", resp.Headers["X-Ratelimit-Remaining-Tokens"][0])
}

func TestIdentifier_FallsBackToIP(t *testing.T) {
	p, mr := setup(t)

	settings := map[string]interface{}{
		"identifier_header": "X-API-Key",
		"window":            map[string]interface{}{"unit": "minute", "max": 100},
	}

	require.NoError(t, mr.Set("trl:test-plugin:192.168.1.1", "80"))
	mr.SetTTL("trl:test-plugin:192.168.1.1", 30_000_000_000)

	req := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PreRequest,
		Headers:  map[string][]string{},
		IP:       "192.168.1.1",
	}
	resp, err := p.Execute(context.Background(), pluginCfg(settings), req, &types.ResponseContext{}, newEvtCtx())
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "20", resp.Headers["X-Ratelimit-Remaining-Tokens"][0])
}

func TestIdentifier_NoHeaderNoIP_UsesGlobal(t *testing.T) {
	p, _ := setup(t)

	req := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PreRequest,
		Headers:  map[string][]string{},
		IP:       "",
	}
	resp, err := p.Execute(context.Background(), pluginCfg(defaultSettings()), req, &types.ResponseContext{}, newEvtCtx())
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "100", resp.Headers["X-Ratelimit-Remaining-Tokens"][0])
}

// ---------------------------------------------------------------------------
// Window TTL reset
// ---------------------------------------------------------------------------

func TestWindowReset_CounterResetsAfterTTLExpires(t *testing.T) {
	p, mr := setup(t)

	openaiResponse := `{
		"id": "chatcmpl-123",
		"object": "chat.completion",
		"model": "gpt-4",
		"choices": [{"message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop", "index": 0}],
		"usage": {"prompt_tokens": 10, "completion_tokens": 40, "total_tokens": 50}
	}`

	cfg := pluginCfg(defaultSettings())
	req := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PostResponse,
		Headers:  map[string][]string{},
		IP:       "10.0.0.1",
	}

	_, err := p.Execute(context.Background(), cfg, req, &types.ResponseContext{Body: []byte(openaiResponse)}, newEvtCtx())
	require.NoError(t, err)

	val, _ := mr.Get("trl:test-plugin:10.0.0.1")
	assert.Equal(t, "50", val)

	mr.FastForward(61_000_000_000) // 61 seconds — past the 60s window

	assert.False(t, mr.Exists("trl:test-plugin:10.0.0.1"), "key should have expired")

	reqPre := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PreRequest,
		Headers:  map[string][]string{},
		IP:       "10.0.0.1",
	}
	resp, err := p.Execute(context.Background(), cfg, reqPre, &types.ResponseContext{}, newEvtCtx())
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "100", resp.Headers["X-Ratelimit-Remaining-Tokens"][0])
}

func TestWindowTTL_NotExtendedOnSubsequentWrites(t *testing.T) {
	p, mr := setup(t)

	openaiResponse := `{
		"id": "chatcmpl-123",
		"object": "chat.completion",
		"model": "gpt-4",
		"choices": [{"message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop", "index": 0}],
		"usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10}
	}`

	cfg := pluginCfg(defaultSettings())
	req := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PostResponse,
		Headers:  map[string][]string{},
		IP:       "10.0.0.1",
	}

	_, err := p.Execute(context.Background(), cfg, req, &types.ResponseContext{Body: []byte(openaiResponse)}, newEvtCtx())
	require.NoError(t, err)

	ttl1 := mr.TTL("trl:test-plugin:10.0.0.1")

	mr.FastForward(20_000_000_000) // 20 seconds forward

	_, err = p.Execute(context.Background(), cfg, req, &types.ResponseContext{Body: []byte(openaiResponse)}, newEvtCtx())
	require.NoError(t, err)

	ttl2 := mr.TTL("trl:test-plugin:10.0.0.1")

	assert.True(t, ttl2 < ttl1, "TTL should have decreased, not been reset (ttl1=%v, ttl2=%v)", ttl1, ttl2)

	val, _ := mr.Get("trl:test-plugin:10.0.0.1")
	assert.Equal(t, "20", val)
}

// ---------------------------------------------------------------------------
// Full flow: PostResponse records → PreRequest rejects
// ---------------------------------------------------------------------------

func TestFullFlow_PostResponseThenPreRequestReject(t *testing.T) {
	p, _ := setup(t)

	settings := map[string]interface{}{
		"window": map[string]interface{}{"unit": "minute", "max": 50},
	}
	cfg := pluginCfg(settings)

	openaiResponse := `{
		"id": "chatcmpl-123",
		"object": "chat.completion",
		"model": "gpt-4",
		"choices": [{"message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop", "index": 0}],
		"usage": {"prompt_tokens": 10, "completion_tokens": 40, "total_tokens": 50}
	}`

	postReq := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PostResponse,
		Headers:  map[string][]string{},
		IP:       "10.0.0.1",
	}
	_, err := p.Execute(context.Background(), cfg, postReq, &types.ResponseContext{Body: []byte(openaiResponse)}, newEvtCtx())
	require.NoError(t, err)

	preReq := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PreRequest,
		Headers:  map[string][]string{},
		IP:       "10.0.0.1",
	}
	resp, err := p.Execute(context.Background(), cfg, preReq, &types.ResponseContext{}, newEvtCtx())
	assert.Nil(t, resp)
	require.Error(t, err)

	var pluginErr *pluginTypes.PluginError
	require.True(t, errors.As(err, &pluginErr))
	assert.Equal(t, http.StatusTooManyRequests, pluginErr.StatusCode)
}

func TestFullFlow_DifferentClients_IndependentCounters(t *testing.T) {
	p, _ := setup(t)

	cfg := pluginCfg(defaultSettings())

	openaiResponse := `{
		"id": "chatcmpl-123",
		"object": "chat.completion",
		"model": "gpt-4",
		"choices": [{"message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop", "index": 0}],
		"usage": {"prompt_tokens": 10, "completion_tokens": 40, "total_tokens": 50}
	}`

	for _, ip := range []string{"10.0.0.1", "10.0.0.2"} {
		postReq := &types.RequestContext{
			Provider: "openai",
			Stage:    pluginTypes.PostResponse,
			Headers:  map[string][]string{},
			IP:       ip,
		}
		_, err := p.Execute(context.Background(), cfg, postReq, &types.ResponseContext{Body: []byte(openaiResponse)}, newEvtCtx())
		require.NoError(t, err)
	}

	for _, ip := range []string{"10.0.0.1", "10.0.0.2"} {
		preReq := &types.RequestContext{
			Provider: "openai",
			Stage:    pluginTypes.PreRequest,
			Headers:  map[string][]string{},
			IP:       ip,
		}
		resp, err := p.Execute(context.Background(), cfg, preReq, &types.ResponseContext{}, newEvtCtx())
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "50", resp.Headers["X-Ratelimit-Remaining-Tokens"][0], "ip=%s should have 50 remaining", ip)
	}
}

// ---------------------------------------------------------------------------
// Unsupported stage
// ---------------------------------------------------------------------------

func TestExecute_UnsupportedStage(t *testing.T) {
	p, _ := setup(t)
	req := &types.RequestContext{
		Provider: "openai",
		Stage:    pluginTypes.PreResponse,
		Headers:  map[string][]string{},
		IP:       "10.0.0.1",
	}
	_, err := p.Execute(context.Background(), pluginCfg(defaultSettings()), req, &types.ResponseContext{}, newEvtCtx())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported stage")
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func itoa(n int) string { return strconv.Itoa(n) }
