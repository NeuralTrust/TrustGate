package anomaly_detector_test

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/anomaly_detector"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func createTestPlugin(t *testing.T, customTracker ...*mocks.Tracker) *anomaly_detector.AnomalyDetectorPlugin {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	var fpTracker *mocks.Tracker
	if len(customTracker) > 0 {
		fpTracker = customTracker[0]
	} else {
		fpTracker = new(mocks.Tracker)
	}

	c := &cache.Cache{}

	plugin := anomaly_detector.NewAnomalyDetectorPlugin(logger, fpTracker, c)

	adPlugin, ok := plugin.(*anomaly_detector.AnomalyDetectorPlugin)
	if !ok {
		t.Fatalf("Expected plugin to be of type *anomaly_detector.AnomalyDetectorPlugin, got %T", plugin)
	}

	return adPlugin
}

func TestAnomalyDetectorPlugin_Name(t *testing.T) {
	plugin := createTestPlugin(t)
	assert.Equal(t, "anomaly_detector", plugin.Name())
}

func TestAnomalyDetectorPlugin_RequiredPlugins(t *testing.T) {
	plugin := createTestPlugin(t)
	assert.Empty(t, plugin.RequiredPlugins())
}

func TestAnomalyDetectorPlugin_Stages(t *testing.T) {
	plugin := createTestPlugin(t)
	stages := plugin.Stages()
	assert.Len(t, stages, 1)
	assert.Equal(t, types.PreRequest, stages[0])
}

func TestAnomalyDetectorPlugin_AllowedStages(t *testing.T) {
	plugin := createTestPlugin(t)
	stages := plugin.AllowedStages()
	assert.Len(t, stages, 1)
	assert.Equal(t, types.PreRequest, stages[0])
}

func TestAnomalyDetectorPlugin_ValidateConfig(t *testing.T) {
	plugin := createTestPlugin(t)

	t.Run("Valid Configuration", func(t *testing.T) {
		config := types.PluginConfig{
			Settings: map[string]interface{}{
				"threshold":                 0.5,
				"action":                    "alert_only",
				"timing_pattern_weight":     0.2,
				"content_similarity_weight": 0.2,
				"suspicious_headers_weight": 0.2,
				"token_usage_weight":        0.4,
			},
		}

		err := plugin.ValidateConfig(config)
		assert.NoError(t, err)
	})

	t.Run("Invalid Threshold - Below 0", func(t *testing.T) {
		config := types.PluginConfig{
			Settings: map[string]interface{}{
				"threshold": -0.1,
				"action":    "alert_only",
			},
		}

		err := plugin.ValidateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "threshold must be between 0 and 1")
	})

	t.Run("Invalid Threshold - Above 1", func(t *testing.T) {
		config := types.PluginConfig{
			Settings: map[string]interface{}{
				"threshold": 1.1,
				"action":    "alert_only",
			},
		}

		err := plugin.ValidateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "threshold must be between 0 and 1")
	})

	t.Run("Invalid Action", func(t *testing.T) {
		config := types.PluginConfig{
			Settings: map[string]interface{}{
				"threshold": 0.5,
				"action":    "invalid_action",
			},
		}

		err := plugin.ValidateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid action")
	})

	t.Run("Weights Don't Sum to 1.0", func(t *testing.T) {
		config := types.PluginConfig{
			Settings: map[string]interface{}{
				"threshold":                 0.5,
				"action":                    "alert_only",
				"timing_pattern_weight":     0.3,
				"content_similarity_weight": 0.3,
				"suspicious_headers_weight": 0.3,
				"token_usage_weight":        0.3,
			},
		}

		err := plugin.ValidateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "weights must sum to 1.0")
	})
}

func TestAnomalyDetectorPlugin_Execute_NoFingerprint(t *testing.T) {
	plugin := createTestPlugin(t)

	req := &types.RequestContext{
		Headers: map[string][]string{},
	}
	resp := &types.ResponseContext{
		Headers: make(map[string][]string),
	}
	evtCtx := metrics.NewEventContext("", "", nil)

	pluginConfig := types.PluginConfig{
		Settings: map[string]interface{}{
			"threshold": 0.5,
			"action":    "alert_only",
		},
	}

	result, err := plugin.Execute(context.Background(), pluginConfig, req, resp, evtCtx)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "no fingerprint to analyze", result.Message)
}
