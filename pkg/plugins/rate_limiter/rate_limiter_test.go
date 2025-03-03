package rate_limiter_test

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

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
	testKey := "ratelimit:global:testID:per_ip:127.0.0.1"
	testWindow := time.Minute
	currentTime := time.Now().Unix()
	windowStart := currentTime - int64(testWindow.Seconds())

	mock.ExpectZCount(testKey, strconv.FormatInt(windowStart, 10), strconv.FormatInt(currentTime, 10)).SetVal(10)

	plugin := rate_limiter.NewRateLimiterPlugin(redisMock, nil)

	cfg := types.PluginConfig{
		ID:    "testID",
		Level: "global",
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

	pluginResponse, err := plugin.Execute(context.Background(), cfg, req, resp)

	assert.Nil(t, pluginResponse)
	assert.Error(t, err)
	assert.Equal(t, http.StatusTooManyRequests, err.(*types.PluginError).StatusCode)
}

func TestRateLimiterPlugin_Execute_NoLimitExceeded(t *testing.T) {
	redisMock, mock := redismock.NewClientMock()
	mock.MatchExpectationsInOrder(false)

	testKey := "ratelimit:global:testID:per_ip:127.0.0.1"
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
		Level: "global",
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

	pluginResponse, err := plugin.Execute(context.Background(), cfg, req, resp)

	assert.Nil(t, pluginResponse)
	assert.NoError(t, err)
}

func TestRateLimiterPlugin_Execute_PerUser_NoLimitExceeded(t *testing.T) {
	redisMock, mock := redismock.NewClientMock()
	testKey := "ratelimit:global:testID:per_user:user123"
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
		Level: "global",
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

	pluginResponse, err := plugin.Execute(context.Background(), cfg, req, resp)

	assert.Nil(t, pluginResponse)
	assert.NoError(t, err)
}
