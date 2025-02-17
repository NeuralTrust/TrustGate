package toxicity_openai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/mitchellh/mapstructure"
)

const (
	PluginName          = "toxicity_openai"
	OpenAIModerationURL = "https://api.openai.com/v1/moderations"
)

type ToxicityOpenAIPlugin struct {
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

func NewToxicityOpenAIPlugin() pluginiface.Plugin {
	plugin := &ToxicityOpenAIPlugin{}
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
		slog.Error("Failed to decode config",
			slog.String("error", err.Error()),
		)
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}

	p.config = config
	slog.Info("Received request for toxicity detection")
	slog.Debug("Request body",
		slog.String("body", string(req.Body)),
	)

	// Parse request body to extract message content
	var requestBody RequestBody
	if err := json.Unmarshal(req.Body, &requestBody); err != nil {
		slog.Error("Failed to parse request body",
			slog.String("error", err.Error()),
		)
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
		slog.Info("No content to moderate")
		return &types.PluginResponse{
			StatusCode: 200,
			Message:    "No content to moderate",
		}, nil
	}

	slog.Debug("Content to moderate",
		slog.Any("inputs", moderationInputs),
	)

	// Create moderation request
	moderationReq := OpenAIModerationRequest{
		Input: moderationInputs,
		Model: "omni-moderation-latest",
	}

	jsonData, err := json.Marshal(moderationReq)
	if err != nil {
		slog.Error("Failed to marshal moderation request",
			slog.String("error", err.Error()),
		)
		return nil, fmt.Errorf("failed to marshal moderation request: %v", err)
	}

	// Create HTTP request to OpenAI
	httpReq, err := http.NewRequestWithContext(ctx, "POST", OpenAIModerationURL, bytes.NewBuffer(jsonData))
	if err != nil {
		slog.Error("Failed to create HTTP request",
			slog.String("error", err.Error()),
		)
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+config.OpenAIKey)

	// Send request
	client := &http.Client{}
	slog.Debug("Sending request to OpenAI moderation endpoint")
	httpResp, err := client.Do(httpReq)
	if err != nil {
		slog.Error("Failed to send moderation request",
			slog.String("error", err.Error()),
		)
		return nil, fmt.Errorf("failed to send moderation request: %v", err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		slog.Error("Failed to read response body",
			slog.String("error", err.Error()),
		)
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	slog.Debug("OpenAI API response",
		slog.String("response", string(body)),
	)

	if httpResp.StatusCode != http.StatusOK {
		slog.Error("OpenAI API returned error",
			slog.Int("status_code", httpResp.StatusCode),
			slog.String("response", string(body)),
		)
		return nil, fmt.Errorf("OpenAI API returned error: %s", string(body))
	}

	// Parse response
	var moderationResp OpenAIModerationResponse
	if err := json.Unmarshal(body, &moderationResp); err != nil {
		slog.Error("Failed to unmarshal moderation response",
			slog.String("error", err.Error()),
		)
		return nil, fmt.Errorf("failed to unmarshal moderation response: %v", err)
	}

	if len(moderationResp.Results) == 0 {
		slog.Error("No moderation results returned")
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
		slog.Info("Content flagged for toxicity",
			slog.Any("categories", flaggedCategories),
			slog.Any("scores", result.CategoryScores),
			slog.Any("applied_types", result.CategoryAppliedInputTypes),
		)
		return nil, &types.PluginError{
			StatusCode: 403,
			Message:    fmt.Sprintf(config.Actions.Message+" Flagged categories: %v", flaggedCategories),
			Err:        fmt.Errorf("content flagged for categories: %v", flaggedCategories),
		}
	}

	slog.Info("Content is safe")
	return &types.PluginResponse{
		StatusCode: 200,
		Message:    "Content is safe",
	}, nil
}
