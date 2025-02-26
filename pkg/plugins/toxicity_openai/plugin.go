package toxicity_openai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

const (
	PluginName          = "toxicity_openai"
	OpenAIModerationURL = "https://api.openai.com/v1/moderations"
)

type ToxicityOpenAIPlugin struct {
	logger *logrus.Logger
	config Config
}

type Config struct {
	OpenAIKey string `mapstructure:"openai_key"`
	Actions   struct {
		Type    string `mapstructure:"type"`
		Message string `mapstructure:"message"`
	} `mapstructure:"actions"`
	Categories []string           `mapstructure:"categories"` // Categories to check for (e.g., "hate", "violence", etc.)
	Thresholds map[string]float64 `mapstructure:"thresholds"` // Score thresholds for each category
}

type RequestBody struct {
	Messages []struct {
		Role    string        `json:"role"`
		Content []ContentItem `json:"content"`
	} `json:"messages"`
}

type ContentItem struct {
	Type     string    `json:"type"`
	Text     string    `json:"text,omitempty"`
	ImageURL *ImageURL `json:"image_url,omitempty"`
}

type ImageURL struct {
	URL string `json:"url"`
}

type OpenAIModerationRequest struct {
	Input []ModerationInput `json:"input"`
	Model string            `json:"model,omitempty"`
}

type ModerationInput struct {
	Type     string    `json:"type"`
	Text     string    `json:"text,omitempty"`
	ImageURL *ImageURL `json:"image_url,omitempty"`
}

type OpenAIModerationResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Results []struct {
		Flagged                   bool                `json:"flagged"`
		Categories                map[string]bool     `json:"categories"`
		CategoryScores            map[string]float64  `json:"category_scores"`
		CategoryAppliedInputTypes map[string][]string `json:"category_applied_input_types"`
	} `json:"results"`
}

func NewToxicityOpenAIPlugin(logger *logrus.Logger) pluginiface.Plugin {
	plugin := &ToxicityOpenAIPlugin{
		logger: logger,
	}
	return plugin
}

func (p *ToxicityOpenAIPlugin) Name() string {
	return PluginName
}

func (p *ToxicityOpenAIPlugin) Stages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *ToxicityOpenAIPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

// ValidateConfig implements the PluginValidator interface
func (p *ToxicityOpenAIPlugin) ValidateConfig(config types.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %v", err)
	}

	if cfg.OpenAIKey == "" {
		return fmt.Errorf("OpenAI API key must be specified")
	}

	if cfg.Actions.Type == "" {
		return fmt.Errorf("action type must be specified")
	}

	return nil
}

func (p *ToxicityOpenAIPlugin) Execute(ctx context.Context, cfg types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) (*types.PluginResponse, error) {
	var config Config
	if err := mapstructure.Decode(cfg.Settings, &config); err != nil {
		p.logger.WithError(err).Error("Failed to decode config")
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}

	p.config = config
	p.logger.Info("Received request for toxicity detection")
	p.logger.WithField("body", string(req.Body)).Debug("Request body")

	// Parse request body to extract message content
	var requestBody RequestBody
	if err := json.Unmarshal(req.Body, &requestBody); err != nil {
		p.logger.WithError(err).Error("Failed to parse request body")
		return nil, fmt.Errorf("failed to parse request body: %v", err)
	}

	// Create moderation inputs array
	var moderationInputs []ModerationInput

	// Process all messages and their content
	for _, msg := range requestBody.Messages {
		for _, content := range msg.Content {
			switch content.Type {
			case "text":
				if content.Text != "" {
					moderationInputs = append(moderationInputs, ModerationInput{
						Type: "text",
						Text: content.Text,
					})
				}
			case "image_url":
				if content.ImageURL != nil && content.ImageURL.URL != "" {
					moderationInputs = append(moderationInputs, ModerationInput{
						Type: "image_url",
						ImageURL: &ImageURL{
							URL: content.ImageURL.URL,
						},
					})
				}
			}
		}
	}

	if len(moderationInputs) == 0 {
		p.logger.Info("No content to moderate")
		return &types.PluginResponse{
			StatusCode: 200,
			Message:    "No content to moderate",
		}, nil
	}

	p.logger.WithField("inputs", moderationInputs).Debug("Content to moderate")

	// Create moderation request
	moderationReq := OpenAIModerationRequest{
		Input: moderationInputs,
		Model: "omni-moderation-latest",
	}

	jsonData, err := json.Marshal(moderationReq)
	if err != nil {
		p.logger.WithError(err).Error("Failed to marshal moderation request")
		return nil, fmt.Errorf("failed to marshal moderation request: %v", err)
	}

	// Create HTTP request to OpenAI
	httpReq, err := http.NewRequestWithContext(ctx, "POST", OpenAIModerationURL, bytes.NewBuffer(jsonData))
	if err != nil {
		p.logger.WithError(err).Error("Failed to create HTTP request")
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+config.OpenAIKey)

	// Send request
	client := &http.Client{}
	p.logger.Debug("Sending request to OpenAI moderation endpoint")
	httpResp, err := client.Do(httpReq)
	if err != nil {
		p.logger.WithError(err).Error("Failed to send moderation request")
		return nil, fmt.Errorf("failed to send moderation request: %v", err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		p.logger.WithError(err).Error("Failed to read response body")
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	p.logger.WithField("response", string(body)).Debug("OpenAI API response")

	if httpResp.StatusCode != http.StatusOK {
		p.logger.WithFields(logrus.Fields{
			"status_code": httpResp.StatusCode,
			"response":    string(body),
		}).Error("OpenAI API returned error")
		return nil, fmt.Errorf("OpenAI API returned error: %s", string(body))
	}

	// Parse response
	var moderationResp OpenAIModerationResponse
	if err := json.Unmarshal(body, &moderationResp); err != nil {
		p.logger.WithError(err).Error("Failed to unmarshal moderation response")
		return nil, fmt.Errorf("failed to unmarshal moderation response: %v", err)
	}

	if len(moderationResp.Results) == 0 {
		p.logger.Error("No moderation results returned")
		return nil, fmt.Errorf("no moderation results returned")
	}

	result := moderationResp.Results[0]

	// Get categories that exceed their thresholds
	var flaggedCategories []string
	for category, score := range result.CategoryScores {
		// Check if this category has a threshold defined and if it was applied to any input
		if threshold, exists := config.Thresholds[category]; exists {
			if score >= threshold && len(result.CategoryAppliedInputTypes[category]) > 0 {
				inputTypes := result.CategoryAppliedInputTypes[category]
				flaggedCategories = append(flaggedCategories, fmt.Sprintf("%s (%.2f, types: %v)", category, score, inputTypes))
			}
		} else if result.Categories[category] && len(result.CategoryAppliedInputTypes[category]) > 0 {
			// If no threshold is defined, fall back to the binary flagged status
			inputTypes := result.CategoryAppliedInputTypes[category]
			flaggedCategories = append(flaggedCategories, fmt.Sprintf("%s (types: %v)", category, inputTypes))
		}
	}

	if len(flaggedCategories) > 0 {
		p.logger.WithFields(logrus.Fields{
			"categories":    flaggedCategories,
			"scores":        result.CategoryScores,
			"applied_types": result.CategoryAppliedInputTypes,
		}).Info("Content flagged for toxicity")
		return nil, &types.PluginError{
			StatusCode: 403,
			Message:    fmt.Sprintf(config.Actions.Message+" Flagged categories: %v", flaggedCategories),
			Err:        fmt.Errorf("content flagged for categories: %v", flaggedCategories),
		}
	}

	p.logger.Info("Content is safe")
	return &types.PluginResponse{
		StatusCode: 200,
		Message:    "Content is safe",
	}, nil
}
