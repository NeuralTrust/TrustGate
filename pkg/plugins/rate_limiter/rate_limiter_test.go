package rate_limiter_test

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/rate_limiter"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/go-redis/redis/v8"
	"github.com/go-redis/redismock/v8"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewRateLimiterPlugin(t *testing.T) {
	redisMock, _ := redismock.NewClientMock()
	plugin := rate_limiter.NewRateLimiterPlugin(redisMock, nil)
	assert.NotNil(t, plugin)
	assert.Implements(t, (*pluginiface.Plugin)(nil), plugin)
}

func TestRateLimiterPlugin_Name(t *testing.T) {
	redisMock, _ := redismock.NewClientMock()
	plugin := rate_limiter.NewRateLimiterPlugin(redisMock, nil)
	assert.Equal(t, "rate_limiter", plugin.Name())
}

func TestRateLimiterPlugin_ValidateConfig(t *testing.T) {
	redisMock, _ := redismock.NewClientMock()
	plugin := rate_limiter.NewRateLimiterPlugin(redisMock, nil)

	validConfig := types.PluginConfig{
		Stage: types.PreRequest,
		Settings: map[string]interface{}{
			"limits": map[string]interface{}{
				"per_ip": map[string]interface{}{
					"limit":  10.0,
					"window": "1m",
				},
			},
			"actions": map[string]interface{}{
				"type": "reject",
			},
		},
	}

	invalidConfig := types.PluginConfig{
		Stage: types.PostResponse,
		Settings: map[string]interface{}{
			"limits": map[string]interface{}{},
		},
	}

	assert.NoError(t, plugin.ValidateConfig(validConfig))
	assert.Error(t, plugin.ValidateConfig(invalidConfig))
}

func TestRateLimiterPlugin_Execute_LimitExceeded(t *testing.T) {
	redisMock, mock := redismock.NewClientMock()
	testKey := "ratelimit:testID:per_ip:127.0.0.1"
	testWindow := time.Minute
	currentTime := time.Now().Unix()
	windowStart := currentTime - int64(testWindow.Seconds())

	mock.ExpectZCount(testKey, strconv.FormatInt(windowStart, 10), strconv.FormatInt(currentTime, 10)).SetVal(10)

	plugin := rate_limiter.NewRateLimiterPlugin(redisMock, nil)

	cfg := types.PluginConfig{
		ID:    "testID",
		Stage: types.PreRequest,
		Settings: map[string]interface{}{
			"limits": map[string]interface{}{
				"per_ip": map[string]interface{}{
					"limit":  10.0,
					"window": "1m",
				},
			},
			"actions": map[string]interface{}{
				"type": "reject",
			},
		},
	}

	req := &types.RequestContext{Headers: map[string][]string{"X-Real-IP": {"127.0.0.1"}}}
	resp := &types.ResponseContext{Headers: make(map[string][]string), Metadata: make(map[string]interface{})}

	pluginResponse, err := plugin.Execute(context.Background(), cfg, req, resp, metrics.NewEventContext("", "", nil))

	assert.Nil(t, pluginResponse)
	assert.Error(t, err)
	if err != nil {
		assert.IsType(t, &types.PluginError{}, err)
		var pluginError *types.PluginError
		ok := errors.As(err, &pluginError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusTooManyRequests, pluginError.StatusCode)
	}
}

func TestRateLimiterPlugin_Execute_NoLimitExceeded(t *testing.T) {
	redisMock, mock := redismock.NewClientMock()
	mock.MatchExpectationsInOrder(false)

	testKey := "ratelimit:testID:per_ip:127.0.0.1"
	testWindow := time.Minute
	fixedTime := time.Unix(1740730536, 0)
	windowStart := fixedTime.Add(-testWindow).Unix()
	uid := uuid.New()

	mock.ExpectZCount(
		testKey,
		strconv.FormatInt(windowStart, 10),
		strconv.FormatInt(fixedTime.Unix(), 10),
	).SetVal(5)
	mock.ExpectTxPipeline()
	mock.ExpectZRemRangeByScore(testKey, "0", strconv.FormatInt(windowStart, 10)).SetVal(1)
	mock.ExpectZAdd(
		testKey,
		&redis.Z{Score: float64(fixedTime.Unix()),
			Member: strconv.FormatInt(fixedTime.Unix(), 10) + ":" + uid.String()},
	).SetVal(1)
	mock.ExpectExpire(testKey, testWindow).SetVal(true)
	mock.ExpectTxPipelineExec()

	plugin := rate_limiter.NewRateLimiterPlugin(redisMock, &rate_limiter.RateLimiterOpts{
		TimeProvider: func() time.Time { return fixedTime },
		UuidProvider: func() uuid.UUID {
			return uid
		},
	})

	cfg := types.PluginConfig{
		ID:    "testID",
		Stage: types.PreRequest,
		Settings: map[string]interface{}{
			"limits": map[string]interface{}{
				"per_ip": map[string]interface{}{
					"limit":  10.0,
					"window": "1m",
				},
			},
			"actions": map[string]interface{}{
				"type": "reject",
			},
		},
	}

	req := &types.RequestContext{Headers: map[string][]string{"X-Real-IP": {"127.0.0.1"}}}
	resp := &types.ResponseContext{Headers: make(map[string][]string), Metadata: make(map[string]interface{})}

	pluginResponse, err := plugin.Execute(context.Background(), cfg, req, resp, metrics.NewEventContext("", "", nil))

	assert.Nil(t, pluginResponse)
	assert.NoError(t, err)
}

func TestRateLimiterPlugin_Execute_PerUser_NoLimitExceeded(t *testing.T) {
	redisMock, mock := redismock.NewClientMock()
	testKey := "ratelimit:testID:per_user:user123"
	testWindow := time.Minute
	fixedTime := time.Unix(1740730536, 0)
	windowStart := fixedTime.Add(-testWindow).Unix()
	fixedUUID := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	mock.MatchExpectationsInOrder(false)
	mock.ExpectZCount(testKey, strconv.FormatInt(windowStart, 10), strconv.FormatInt(fixedTime.Unix(), 10)).SetVal(5)
	mock.ExpectTxPipeline()
	mock.ExpectZRemRangeByScore(testKey, "0", strconv.FormatInt(windowStart, 10)).SetVal(1)
	mock.ExpectZAdd(testKey, &redis.Z{Score: float64(fixedTime.Unix()), Member: strconv.FormatInt(fixedTime.Unix(), 10) + ":" + fixedUUID.String()}).SetVal(1)
	mock.ExpectExpire(testKey, testWindow).SetVal(true)
	mock.ExpectTxPipelineExec()

	plugin := rate_limiter.NewRateLimiterPlugin(redisMock, &rate_limiter.RateLimiterOpts{
		TimeProvider: func() time.Time { return fixedTime },
		UuidProvider: func() uuid.UUID { return fixedUUID },
	})

	cfg := types.PluginConfig{
		ID:    "testID",
		Stage: types.PreRequest,
		Settings: map[string]interface{}{
			"limits": map[string]interface{}{
				"per_user": map[string]interface{}{
					"limit":  10.0,
					"window": "1m",
				},
			},
			"actions": map[string]interface{}{
				"type": "reject",
			},
		},
	}

	req := &types.RequestContext{Headers: map[string][]string{"X-User-ID": {"user123"}}}
	resp := &types.ResponseContext{Headers: make(map[string][]string), Metadata: make(map[string]interface{})}

	pluginResponse, err := plugin.Execute(context.Background(), cfg, req, resp, metrics.NewEventContext("", "", nil))

	assert.Nil(t, pluginResponse)
	assert.NoError(t, err)
}

func TestRateLimiterPlugin_Execute_PerFingerprint_LimitExceeded(t *testing.T) {
	redisMock, mock := redismock.NewClientMock()
	testKey := "ratelimit:testID:per_fingerprint:test-fingerprint-id"
	testWindow := time.Minute
	currentTime := time.Now().Unix()
	windowStart := currentTime - int64(testWindow.Seconds())

	mock.ExpectZCount(testKey, strconv.FormatInt(windowStart, 10), strconv.FormatInt(currentTime, 10)).SetVal(5)

	plugin := rate_limiter.NewRateLimiterPlugin(redisMock, nil)

	cfg := types.PluginConfig{
		ID:    "testID",
		Stage: types.PreRequest,
		Settings: map[string]interface{}{
			"limits": map[string]interface{}{
				"per_fingerprint": map[string]interface{}{
					"limit":  5.0,
					"window": "1m",
				},
			},
			"actions": map[string]interface{}{
				"type": "reject",
			},
		},
	}

	// Create context with fingerprint ID
	ctx := context.WithValue(context.Background(), common.FingerprintIdContextKey, "test-fingerprint-id")
	req := &types.RequestContext{Headers: map[string][]string{}}
	resp := &types.ResponseContext{Headers: make(map[string][]string), Metadata: make(map[string]interface{})}

	pluginResponse, err := plugin.Execute(ctx, cfg, req, resp, metrics.NewEventContext("", "", nil))

	assert.Nil(t, pluginResponse)
	assert.Error(t, err)
	if err != nil {
		assert.IsType(t, &types.PluginError{}, err)
		var pluginError *types.PluginError
		ok := errors.As(err, &pluginError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusTooManyRequests, pluginError.StatusCode)
		assert.Contains(t, pluginError.Message, "per_fingerprint rate limit exceeded")
	}
}

func TestRateLimiterPlugin_Execute_PerFingerprint_NoLimitExceeded(t *testing.T) {
	redisMock, mock := redismock.NewClientMock()
	mock.MatchExpectationsInOrder(false)

	testKey := "ratelimit:testID:per_fingerprint:test-fingerprint-id"
	testWindow := time.Minute
	fixedTime := time.Unix(1740730536, 0)
	windowStart := fixedTime.Add(-testWindow).Unix()
	uid := uuid.New()

	mock.ExpectZCount(
		testKey,
		strconv.FormatInt(windowStart, 10),
		strconv.FormatInt(fixedTime.Unix(), 10),
	).SetVal(3)
	mock.ExpectTxPipeline()
	mock.ExpectZRemRangeByScore(testKey, "0", strconv.FormatInt(windowStart, 10)).SetVal(1)
	mock.ExpectZAdd(
		testKey,
		&redis.Z{Score: float64(fixedTime.Unix()),
			Member: strconv.FormatInt(fixedTime.Unix(), 10) + ":" + uid.String()},
	).SetVal(1)
	mock.ExpectExpire(testKey, testWindow).SetVal(true)
	mock.ExpectTxPipelineExec()

	plugin := rate_limiter.NewRateLimiterPlugin(redisMock, &rate_limiter.RateLimiterOpts{
		TimeProvider: func() time.Time { return fixedTime },
		UuidProvider: func() uuid.UUID {
			return uid
		},
	})

	cfg := types.PluginConfig{
		ID:    "testID",
		Stage: types.PreRequest,
		Settings: map[string]interface{}{
			"limits": map[string]interface{}{
				"per_fingerprint": map[string]interface{}{
					"limit":  5.0,
					"window": "1m",
				},
			},
			"actions": map[string]interface{}{
				"type": "reject",
			},
		},
	}

	// Create context with fingerprint ID
	ctx := context.WithValue(context.Background(), common.FingerprintIdContextKey, "test-fingerprint-id")
	req := &types.RequestContext{Headers: map[string][]string{}}
	resp := &types.ResponseContext{Headers: make(map[string][]string), Metadata: make(map[string]interface{})}

	pluginResponse, err := plugin.Execute(ctx, cfg, req, resp, metrics.NewEventContext("", "", nil))

	assert.Nil(t, pluginResponse)
	assert.NoError(t, err)
}

func TestRateLimiterPlugin_Execute_PerFingerprint_NoFingerprintInContext(t *testing.T) {
	redisMock, mock := redismock.NewClientMock()
	mock.MatchExpectationsInOrder(false)

	testKey := "ratelimit:testID:per_fingerprint:unknown"
	testWindow := time.Minute
	fixedTime := time.Unix(1740730536, 0)
	windowStart := fixedTime.Add(-testWindow).Unix()
	uid := uuid.New()

	mock.ExpectZCount(
		testKey,
		strconv.FormatInt(windowStart, 10),
		strconv.FormatInt(fixedTime.Unix(), 10),
	).SetVal(2)
	mock.ExpectTxPipeline()
	mock.ExpectZRemRangeByScore(testKey, "0", strconv.FormatInt(windowStart, 10)).SetVal(1)
	mock.ExpectZAdd(
		testKey,
		&redis.Z{Score: float64(fixedTime.Unix()),
			Member: strconv.FormatInt(fixedTime.Unix(), 10) + ":" + uid.String()},
	).SetVal(1)
	mock.ExpectExpire(testKey, testWindow).SetVal(true)
	mock.ExpectTxPipelineExec()

	plugin := rate_limiter.NewRateLimiterPlugin(redisMock, &rate_limiter.RateLimiterOpts{
		TimeProvider: func() time.Time { return fixedTime },
		UuidProvider: func() uuid.UUID {
			return uid
		},
	})

	cfg := types.PluginConfig{
		ID:    "testID",
		Stage: types.PreRequest,
		Settings: map[string]interface{}{
			"limits": map[string]interface{}{
				"per_fingerprint": map[string]interface{}{
					"limit":  5.0,
					"window": "1m",
				},
			},
			"actions": map[string]interface{}{
				"type": "reject",
			},
		},
	}

	// Context without fingerprint ID - should use "unknown" as key
	ctx := context.Background()
	req := &types.RequestContext{Headers: map[string][]string{}}
	resp := &types.ResponseContext{Headers: make(map[string][]string), Metadata: make(map[string]interface{})}

	pluginResponse, err := plugin.Execute(ctx, cfg, req, resp, metrics.NewEventContext("", "", nil))

	assert.Nil(t, pluginResponse)
	assert.NoError(t, err)
}

func TestRateLimiterPlugin_Execute_MultipleLimits_PerFingerprintFirst(t *testing.T) {
	redisMock, mock := redismock.NewClientMock()
	mock.MatchExpectationsInOrder(false)

	// per_fingerprint limit exceeded
	testKey := "ratelimit:testID:per_fingerprint:test-fingerprint-id"
	testWindow := time.Minute
	currentTime := time.Now().Unix()
	windowStart := currentTime - int64(testWindow.Seconds())

	mock.ExpectZCount(testKey, strconv.FormatInt(windowStart, 10), strconv.FormatInt(currentTime, 10)).SetVal(3)

	plugin := rate_limiter.NewRateLimiterPlugin(redisMock, nil)

	cfg := types.PluginConfig{
		ID:    "testID",
		Stage: types.PreRequest,
		Settings: map[string]interface{}{
			"limits": map[string]interface{}{
				"per_fingerprint": map[string]interface{}{
					"limit":  3.0,
					"window": "1m",
				},
				"per_ip": map[string]interface{}{
					"limit":  10.0,
					"window": "1m",
				},
				"global": map[string]interface{}{
					"limit":  100.0,
					"window": "1m",
				},
			},
			"actions": map[string]interface{}{
				"type": "reject",
			},
		},
	}

	// Create context with fingerprint ID
	ctx := context.WithValue(context.Background(), common.FingerprintIdContextKey, "test-fingerprint-id")
	req := &types.RequestContext{Headers: map[string][]string{"X-Real-IP": {"127.0.0.1"}}}
	resp := &types.ResponseContext{Headers: make(map[string][]string), Metadata: make(map[string]interface{})}

	pluginResponse, err := plugin.Execute(ctx, cfg, req, resp, metrics.NewEventContext("", "", nil))

	assert.Nil(t, pluginResponse)
	assert.Error(t, err)
	if err != nil {
		assert.IsType(t, &types.PluginError{}, err)
		var pluginError *types.PluginError
		ok := errors.As(err, &pluginError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusTooManyRequests, pluginError.StatusCode)
		assert.Contains(t, pluginError.Message, "per_fingerprint rate limit exceeded")
	}
}

func TestRateLimiterPlugin_ValidateConfig_PerFingerprint(t *testing.T) {
	redisMock, _ := redismock.NewClientMock()
	plugin := rate_limiter.NewRateLimiterPlugin(redisMock, nil)

	validConfig := types.PluginConfig{
		Stage: types.PreRequest,
		Settings: map[string]interface{}{
			"limits": map[string]interface{}{
				"per_fingerprint": map[string]interface{}{
					"limit":  10.0,
					"window": "1m",
				},
			},
			"actions": map[string]interface{}{
				"type": "reject",
			},
		},
	}

	assert.NoError(t, plugin.ValidateConfig(validConfig))
}
