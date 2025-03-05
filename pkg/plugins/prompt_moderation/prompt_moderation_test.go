package prompt_moderation

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestPromptModerationPlugin_ValidateConfig(t *testing.T) {
	plugin := NewPromptModerationPlugin(logrus.New())

	validConfig := types.PluginConfig{
		Settings: map[string]interface{}{
			"keywords": []string{"badword"},
			"regex":    []string{".*forbidden.*"},
			"actions": map[string]interface{}{
				"type":    "reject",
				"message": "Forbidden content detected",
			},
		},
	}

	invalidConfig := types.PluginConfig{
		Settings: map[string]interface{}{},
	}

	assert.NoError(t, plugin.ValidateConfig(validConfig))
	assert.Error(t, plugin.ValidateConfig(invalidConfig))
}

func TestPromptModerationPlugin_Execute_NoViolation(t *testing.T) {
	plugin := NewPromptModerationPlugin(logrus.New())

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"keywords": []string{"badword"},
			"regex":    []string{".*forbidden.*"},
			"actions": map[string]interface{}{
				"type":    "reject",
				"message": "Forbidden content detected",
			},
		},
	}

	req := &types.RequestContext{Body: []byte("This is a clean message.")}
	resp := &types.ResponseContext{}

	pluginResponse, err := plugin.Execute(context.Background(), cfg, req, resp)

	assert.NotNil(t, pluginResponse)
	assert.NoError(t, err)
}

func TestPromptModerationPlugin_Execute_KeywordViolation(t *testing.T) {
	plugin := NewPromptModerationPlugin(logrus.New())

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"keywords": []string{"badword"},
			"actions": map[string]interface{}{
				"type":    "reject",
				"message": "Forbidden content detected",
			},
		},
	}

	req := &types.RequestContext{Body: []byte("This message contains badword.")}
	resp := &types.ResponseContext{}

	pluginResponse, err := plugin.Execute(context.Background(), cfg, req, resp)

	assert.Nil(t, pluginResponse)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "badword")
}

func TestPromptModerationPlugin_Execute_RegexViolation(t *testing.T) {
	plugin := NewPromptModerationPlugin(logrus.New())

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"regex": []string{".*forbidden.*"},
			"actions": map[string]interface{}{
				"type":    "reject",
				"message": "Forbidden content detected",
			},
		},
	}

	req := &types.RequestContext{Body: []byte("This message contains forbidden content.")}
	resp := &types.ResponseContext{}

	pluginResponse, err := plugin.Execute(context.Background(), cfg, req, resp)

	assert.Nil(t, pluginResponse)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestLevenshteinDistance(t *testing.T) {
	assert.Equal(t, 0, levenshteinDistance("test", "test"))
	assert.Equal(t, 1, levenshteinDistance("test", "text"))
	assert.Equal(t, 3, levenshteinDistance("kitten", "sitting"))
}

func TestCalculateSimilarity(t *testing.T) {
	assert.Equal(t, 1.0, calculateSimilarity("test", "test"))
	assert.Greater(t, calculateSimilarity("test", "text"), 0.7)
	assert.Less(t, calculateSimilarity("kitten", "sitting"), 0.6)
}

func TestFindSimilarKeyword(t *testing.T) {
	plugin := &PromptModerationPlugin{
		keywords: []string{"forbidden", "banned"},
	}

	word, keyword, found := plugin.findSimilarKeyword("This message contains forbidden", 0.8)
	assert.True(t, found)
	assert.Equal(t, "forbidden", word)
	assert.Equal(t, "forbidden", keyword)
}

func TestPluginMetadata(t *testing.T) {
	plugin := NewPromptModerationPlugin(logrus.New())
	assert.Equal(t, "prompt_moderation", plugin.Name())
	assert.ElementsMatch(t, []types.Stage{types.PreRequest}, plugin.Stages())
	assert.ElementsMatch(t, []types.Stage{types.PreRequest}, plugin.AllowedStages())
}
