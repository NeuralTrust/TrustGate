package bot_detector_test

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/bot_detector"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestBotDetectorPlugin_Name(t *testing.T) {
	logger := logrus.New()
	fpTracker := &mocks.Tracker{}
	plugin := bot_detector.NewBotDetectorPlugin(logger, fpTracker)

	assert.Equal(t, "bot_detector", plugin.Name())
}

func TestBotDetectorPlugin_RequiredPlugins(t *testing.T) {
	logger := logrus.New()
	fpTracker := &mocks.Tracker{}
	plugin := bot_detector.NewBotDetectorPlugin(logger, fpTracker)

	assert.Empty(t, plugin.RequiredPlugins())
}

func TestBotDetectorPlugin_Stages(t *testing.T) {
	logger := logrus.New()
	fpTracker := &mocks.Tracker{}
	plugin := bot_detector.NewBotDetectorPlugin(logger, fpTracker)

	stages := plugin.Stages()
	assert.Len(t, stages, 1)
	assert.Equal(t, types.PreRequest, stages[0])
}

func TestBotDetectorPlugin_AllowedStages(t *testing.T) {
	logger := logrus.New()
	fpTracker := &mocks.Tracker{}
	plugin := bot_detector.NewBotDetectorPlugin(logger, fpTracker)

	stages := plugin.AllowedStages()
	assert.Len(t, stages, 1)
	assert.Equal(t, types.PreRequest, stages[0])
}

func TestBotDetectorPlugin_ValidateConfig(t *testing.T) {
	logger := logrus.New()
	fpTracker := &mocks.Tracker{}
	plugin := bot_detector.NewBotDetectorPlugin(logger, fpTracker)

	t.Run("Valid Configuration", func(t *testing.T) {
		config := types.PluginConfig{
			Settings: map[string]interface{}{
				"threshold": 0.5,
				"action":    "alert_only",
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
}

func TestBotDetectorPlugin_CalculateBotScore(t *testing.T) {
	logger := logrus.New()
	fpTracker := &mocks.Tracker{}
	plugin := bot_detector.NewBotDetectorPlugin(logger, fpTracker)

	t.Run("High Bot Score - Multiple Suspicious Factors", func(t *testing.T) {
		data := map[string]interface{}{
			"automationDetection": map[string]interface{}{
				"webdriver":      true,
				"chromeHeadless": true,
				"automationProperties": map[string]interface{}{
					"property1": true,
					"property2": true,
				},
				"inconsistencies": map[string]interface{}{
					"exactCommonResolution":      true,
					"utcTimezone":                true,
					"missingHardwareConcurrency": true,
					"missingDeviceMemory":        true,
					"platformInconsistency":      true,
				},
			},
			"persistenceChecker": map[string]interface{}{
				"cookiesEnabled": false,
				"localStorage":   false,
				"sessionStorage": false,
			},
			"environment": map[string]interface{}{
				"userAgent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
				"languages": []interface{}{},
			},
			"visualFingerprint": map[string]interface{}{
				"canvasFingerprint": "",
				"webglFingerprint": map[string]interface{}{
					"supported": false,
				},
			},
		}

		// Use reflection to access the private method
		var cfg bot_detector.Config
		err := mapstructure.Decode(map[string]interface{}{
			"threshold": 0.5,
			"action":    "alert_only",
		}, &cfg)
		require.NoError(t, err, "Failed to decode config")

		// Create a request context with the trustgate data header
		jsonData, err := json.Marshal(data)
		require.NoError(t, err, "Failed to marshal data")

		// Compress the data with zlib
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		_, err = w.Write(jsonData)
		require.NoError(t, err, "Failed to write compressed data")
		err = w.Close()
		require.NoError(t, err, "Failed to close zlib writer")

		encodedData := base64.StdEncoding.EncodeToString(b.Bytes())
		req := &types.RequestContext{
			Headers: map[string][]string{
				bot_detector.TrustgateDataHeader: {encodedData},
			},
		}
		resp := &types.ResponseContext{
			Headers: make(map[string][]string),
		}
		evtCtx := metrics.NewEventContext("", "", nil)

		// Execute the plugin
		pluginConfig := types.PluginConfig{
			Settings: map[string]interface{}{
				"threshold": 0.5,
				"action":    "alert_only",
			},
		}

		result, err := plugin.Execute(context.Background(), pluginConfig, req, resp, evtCtx)
		require.NoError(t, err)
		require.NotNil(t, result)

		// Check that the bot was detected
		botDetected, ok := result.Headers["bot_detected"]
		assert.True(t, ok)
		assert.Equal(t, []string{"true"}, botDetected)
	})

	t.Run("Low Bot Score - Few Suspicious Factors", func(t *testing.T) {
		data := map[string]interface{}{
			"automationDetection": map[string]interface{}{
				"webdriver":      false,
				"chromeHeadless": false,
				"automationProperties": map[string]interface{}{
					"property1": false,
					"property2": false,
				},
				"inconsistencies": map[string]interface{}{
					"exactCommonResolution":      false,
					"utcTimezone":                false,
					"missingHardwareConcurrency": false,
					"missingDeviceMemory":        false,
					"platformInconsistency":      false,
				},
			},
			"persistenceChecker": map[string]interface{}{
				"cookiesEnabled": true,
				"localStorage":   true,
				"sessionStorage": true,
			},
			"environment": map[string]interface{}{
				"userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
				"languages": []interface{}{"en-US", "en"},
			},
			"visualFingerprint": map[string]interface{}{
				"canvasFingerprint": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA",
				"webglFingerprint": map[string]interface{}{
					"supported": true,
				},
			},
		}

		// Create a request context with the trustgate data header
		jsonData, err := json.Marshal(data)
		require.NoError(t, err, "Failed to marshal data")

		// Compress the data with zlib
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		_, err = w.Write(jsonData)
		require.NoError(t, err, "Failed to write compressed data")
		err = w.Close()
		require.NoError(t, err, "Failed to close zlib writer")

		encodedData := base64.StdEncoding.EncodeToString(b.Bytes())
		req := &types.RequestContext{
			Headers: map[string][]string{
				bot_detector.TrustgateDataHeader: {encodedData},
			},
		}
		resp := &types.ResponseContext{
			Headers: make(map[string][]string),
		}
		evtCtx := metrics.NewEventContext("", "", nil)

		// Execute the plugin
		pluginConfig := types.PluginConfig{
			Settings: map[string]interface{}{
				"threshold": 0.5,
				"action":    "alert_only",
			},
		}

		result, err := plugin.Execute(context.Background(), pluginConfig, req, resp, evtCtx)
		require.NoError(t, err)
		require.NotNil(t, result)

		// Check that the bot was not detected
		_, ok := result.Headers["bot_detected"]
		assert.False(t, ok)
	})
}

func TestBotDetectorPlugin_Execute_NoHeader(t *testing.T) {
	t.Run("No header and no body data", func(t *testing.T) {
		logger := logrus.New()
		fpTracker := &mocks.Tracker{}
		plugin := bot_detector.NewBotDetectorPlugin(logger, fpTracker)

		req := &types.RequestContext{
			Headers: map[string][]string{},
			Body:    []byte{}, // Empty body
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
		assert.Nil(t, result)
	})

	t.Run("No header but with body data", func(t *testing.T) {
		logger := logrus.New()
		fpTracker := &mocks.Tracker{}
		plugin := bot_detector.NewBotDetectorPlugin(logger, fpTracker)

		// Create test data similar to what's used in other tests
		data := map[string]interface{}{
			"automationDetection": map[string]interface{}{
				"webdriver":      true,
				"chromeHeadless": true,
			},
		}
		jsonData, err := json.Marshal(data)
		assert.NoError(t, err, "Failed to marshal data")

		// Compress the data with zlib
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		_, err = w.Write(jsonData)
		assert.NoError(t, err, "Failed to write compressed data")
		err = w.Close()
		assert.NoError(t, err, "Failed to close zlib writer")

		// Base64 encode the compressed data
		encodedData := base64.StdEncoding.EncodeToString(b.Bytes())

		// Create a request body with botDetectionData
		bodyData := map[string]interface{}{
			"botDetectionData": encodedData,
		}
		bodyBytes, err := json.Marshal(bodyData)
		assert.NoError(t, err, "Failed to marshal body data")

		req := &types.RequestContext{
			Headers: map[string][]string{},
			Body:    bodyBytes,
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

		// Check that the bot was detected (since we included bot indicators in the data)
		botDetected, ok := result.Headers["bot_detected"]
		assert.True(t, ok)
		assert.Equal(t, []string{"true"}, botDetected)
	})
}

func TestBotDetectorPlugin_Execute_InvalidHeader(t *testing.T) {
	logger := logrus.New()
	fpTracker := &mocks.Tracker{}
	plugin := bot_detector.NewBotDetectorPlugin(logger, fpTracker)

	req := &types.RequestContext{
		Headers: map[string][]string{
			bot_detector.TrustgateDataHeader: {"invalid-base64"},
		},
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
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to decode trustgate data")
}

func TestBotDetectorPlugin_Execute_Actions(t *testing.T) {
	// Create a high bot score data
	data := map[string]interface{}{
		"automationDetection": map[string]interface{}{
			"webdriver":      true,
			"chromeHeadless": true,
			"automationProperties": map[string]interface{}{
				"property1": true,
				"property2": true,
			},
			"inconsistencies": map[string]interface{}{
				"exactCommonResolution":      true,
				"utcTimezone":                true,
				"missingHardwareConcurrency": true,
				"missingDeviceMemory":        true,
				"platformInconsistency":      true,
			},
		},
		"persistenceChecker": map[string]interface{}{
			"cookiesEnabled": false,
			"localStorage":   false,
			"sessionStorage": false,
		},
		"environment": map[string]interface{}{
			"userAgent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			"languages": []interface{}{},
		},
		"visualFingerprint": map[string]interface{}{
			"canvasFingerprint": "",
			"webglFingerprint": map[string]interface{}{
				"supported": false,
			},
		},
	}

	jsonData, err := json.Marshal(data)
	assert.NoError(t, err, "Failed to marshal data")

	// Compress the data with zlib
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	_, err = w.Write(jsonData)
	assert.NoError(t, err, "Failed to write compressed data")
	err = w.Close()
	assert.NoError(t, err, "Failed to close zlib writer")

	encodedData := base64.StdEncoding.EncodeToString(b.Bytes())

	t.Run("AlertOnly Action", func(t *testing.T) {
		logger := logrus.New()
		fpTracker := &mocks.Tracker{}
		plugin := bot_detector.NewBotDetectorPlugin(logger, fpTracker)

		req := &types.RequestContext{
			Headers: map[string][]string{
				bot_detector.TrustgateDataHeader: {encodedData},
			},
		}
		resp := &types.ResponseContext{
			Headers: make(map[string][]string),
		}
		evtCtx := metrics.NewEventContext("", "", nil)

		pluginConfig := types.PluginConfig{
			Settings: map[string]interface{}{
				"threshold": 0.1, // Low threshold to ensure detection
				"action":    "alert_only",
			},
		}

		result, err := plugin.Execute(context.Background(), pluginConfig, req, resp, evtCtx)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "request has fraudulent activity", result.Message)
		assert.Equal(t, []string{"true"}, result.Headers["bot_detected"])
	})

	t.Run("Throttle Action", func(t *testing.T) {
		logger := logrus.New()
		fpTracker := &mocks.Tracker{}
		plugin := bot_detector.NewBotDetectorPlugin(logger, fpTracker)

		req := &types.RequestContext{
			Headers: map[string][]string{
				bot_detector.TrustgateDataHeader: {encodedData},
			},
		}
		resp := &types.ResponseContext{
			Headers: make(map[string][]string),
		}
		evtCtx := metrics.NewEventContext("", "", nil)

		pluginConfig := types.PluginConfig{
			Settings: map[string]interface{}{
				"threshold": 0.1, // Low threshold to ensure detection
				"action":    "throttle",
			},
		}

		startTime := time.Now()
		result, err := plugin.Execute(context.Background(), pluginConfig, req, resp, evtCtx)
		duration := time.Since(startTime)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "request has fraudulent activity", result.Message)
		assert.Equal(t, []string{"true"}, result.Headers["bot_detected"])
		assert.GreaterOrEqual(t, duration.Seconds(), 1.0) // Should have throttled for at least 1 second
	})

	t.Run("Block Action", func(t *testing.T) {
		logger := logrus.New()
		fpTracker := &mocks.Tracker{}
		plugin := bot_detector.NewBotDetectorPlugin(logger, fpTracker)

		// Setup fingerprint mock
		ctx := context.WithValue(context.Background(), common.FingerprintIdContextKey, "test-fingerprint-id")
		fp := &fingerprint.Fingerprint{
			UserID:    "test-user",
			Token:     "test-token",
			IP:        "127.0.0.1",
			UserAgent: "test-agent",
		}
		fpTracker.On("GetFingerprint", mock.Anything, "test-fingerprint-id").Return(fp, nil)
		fpTracker.On("IncrementMaliciousCount", mock.Anything, "test-fingerprint-id", mock.Anything).Return(nil)

		req := &types.RequestContext{
			Headers: map[string][]string{
				bot_detector.TrustgateDataHeader: {encodedData},
			},
		}
		resp := &types.ResponseContext{
			Headers: make(map[string][]string),
		}
		evtCtx := metrics.NewEventContext("", "", nil)

		pluginConfig := types.PluginConfig{
			Settings: map[string]interface{}{
				"threshold":        0.1, // Low threshold to ensure detection
				"action":           "block",
				"retention_period": 300,
			},
		}

		result, err := plugin.Execute(ctx, pluginConfig, req, resp, evtCtx)
		assert.Error(t, err)
		assert.Nil(t, result)

		// Check that it's a PluginError with the correct status code
		pluginErr, ok := err.(*types.PluginError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusForbidden, pluginErr.StatusCode)
		assert.Equal(t, "blocked request due fraudulent activity", pluginErr.Message)
		assert.Equal(t, []string{"true"}, pluginErr.Headers["bot_detected"])

		// Verify that the fingerprint was incremented
		fpTracker.AssertCalled(t, "GetFingerprint", mock.Anything, "test-fingerprint-id")
		fpTracker.AssertCalled(t, "IncrementMaliciousCount", mock.Anything, "test-fingerprint-id", 300*time.Second)
	})
}

func TestBotDetectorPlugin_Execute_WithFingerprint(t *testing.T) {
	logger := logrus.New()
	fpTracker := &mocks.Tracker{}
	plugin := bot_detector.NewBotDetectorPlugin(logger, fpTracker)

	// Create a low bot score data
	data := map[string]interface{}{
		"automationDetection": map[string]interface{}{
			"webdriver":      false,
			"chromeHeadless": false,
		},
		"persistenceChecker": map[string]interface{}{
			"cookiesEnabled": true,
			"localStorage":   true,
			"sessionStorage": true,
		},
		"environment": map[string]interface{}{
			"userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			"languages": []interface{}{"en-US", "en"},
		},
	}

	jsonData, err := json.Marshal(data)
	assert.NoError(t, err, "Failed to marshal data")

	// Compress the data with zlib
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	_, err = w.Write(jsonData)
	assert.NoError(t, err, "Failed to write compressed data")
	err = w.Close()
	assert.NoError(t, err, "Failed to close zlib writer")

	encodedData := base64.StdEncoding.EncodeToString(b.Bytes())

	// Setup fingerprint mock
	ctx := context.WithValue(context.Background(), common.FingerprintIdContextKey, "test-fingerprint-id")
	fp := &fingerprint.Fingerprint{
		UserID:    "test-user",
		Token:     "test-token",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}
	fpTracker.On("GetFingerprint", mock.Anything, "test-fingerprint-id").Return(fp, nil)

	req := &types.RequestContext{
		Headers: map[string][]string{
			bot_detector.TrustgateDataHeader: {encodedData},
		},
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

	result, err := plugin.Execute(ctx, pluginConfig, req, resp, evtCtx)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Check that the fingerprint was retrieved
	fpTracker.AssertCalled(t, "GetFingerprint", mock.Anything, "test-fingerprint-id")

	// Check that the event context has the fingerprint
	// Since we can't access the extras field directly, we'll just verify that the plugin executed successfully
	// and that the fingerprint was retrieved
}
