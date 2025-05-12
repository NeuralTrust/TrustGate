package toxicity_openai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
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
	client httpx.Client
	logger *logrus.Logger
	config Config
}

type Config struct {
	OpenAIKey  string             `mapstructure:"openai_key"`
	Actions    ActionConfig       `mapstructure:"actions"`
	Categories []string           `mapstructure:"categories"`
	Thresholds map[string]float64 `mapstructure:"thresholds"`
}

type ActionConfig struct {
	Type    string `mapstructure:"type"`
	Message string `mapstructure:"message"`
}

type RequestBody struct {
	Messages []Message `json:"messages"`
}

type Message struct {
	Role    string        `json:"role"`
	Content []ContentItem `json:"content"`
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
	ID      string             `json:"id"`
	Model   string             `json:"model"`
	Results []ModerationResult `json:"results"`
}

type ModerationResult struct {
	Flagged                   bool                `json:"flagged"`
	Categories                map[string]bool     `json:"categories"`
	CategoryScores            map[string]float64  `json:"category_scores"`
	CategoryAppliedInputTypes map[string][]string `json:"category_applied_input_types"`
}

func NewToxicityOpenAIPlugin(
	logger *logrus.Logger,
	client httpx.Client,
) pluginiface.Plugin {
	if client == nil {
		client = &http.Client{}
	}
	return &ToxicityOpenAIPlugin{
		client: client,
		logger: logger,
	}
}

func (p *ToxicityOpenAIPlugin) Name() string {
	return PluginName
}

func (p *ToxicityOpenAIPlugin) RequiredPlugins() []string {
	var requiredPlugins []string
	return requiredPlugins
}

func (p *ToxicityOpenAIPlugin) SetUp(config types.PluginConfig) error {
	return nil
}

func (p *ToxicityOpenAIPlugin) Stages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *ToxicityOpenAIPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *ToxicityOpenAIPlugin) ValidateConfig(config types.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}
	if cfg.Actions.Type == "" {
		return fmt.Errorf("action type must be specified")
	}
	if cfg.OpenAIKey == "" {
		return fmt.Errorf("OpenAI API key must be specified")
	}
	return nil
}

func (p *ToxicityOpenAIPlugin) Execute(
	ctx context.Context,
	cfg types.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	collector *metrics.Collector,
) (*types.PluginResponse, error) {
	var conf Config
	if err := mapstructure.Decode(cfg.Settings, &conf); err != nil {
		p.logger.WithError(err).Error("Failed to decode config")
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}
	p.config = conf

	var requestBody RequestBody
	if err := json.Unmarshal(req.Body, &requestBody); err != nil {
		return nil, fmt.Errorf("failed to parse request body: %w", err)
	}

	moderationInputs := p.extractModerationInputs(requestBody.Messages)
	if len(moderationInputs) == 0 {
		return &types.PluginResponse{StatusCode: 200, Message: "No content to moderate"}, nil
	}

	moderationReq := OpenAIModerationRequest{Input: moderationInputs, Model: "omni-moderation-latest"}
	jsonData, err := json.Marshal(moderationReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal moderation request: %w", err)
	}

	httpResp, err := p.sendModerationRequest(ctx, conf.OpenAIKey, jsonData)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		p.raiseEvent(collector, ToxicityOpenaiData{Flagged: true, Response: body}, req.Stage, true, string(body))
		return nil, fmt.Errorf("OpenAI API returned error: %s", string(body))
	}

	p.raiseEvent(collector, ToxicityOpenaiData{Flagged: false, Response: body}, req.Stage, false, "")

	var moderationResp OpenAIModerationResponse
	if err := json.Unmarshal(body, &moderationResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal moderation response: %w", err)
	}

	return p.analyzeModerationResponse(moderationResp.Results)
}

func (p *ToxicityOpenAIPlugin) extractModerationInputs(messages []Message) []ModerationInput {
	var inputs []ModerationInput
	for _, msg := range messages {
		for _, content := range msg.Content {
			if content.Type == "text" && content.Text != "" {
				inputs = append(inputs, ModerationInput{Type: "text", Text: content.Text})
			} else if content.Type == "image_url" && content.ImageURL != nil {
				inputs = append(inputs, ModerationInput{Type: "image_url", ImageURL: content.ImageURL})
			}
		}
	}
	return inputs
}

func (p *ToxicityOpenAIPlugin) sendModerationRequest(ctx context.Context, key string, jsonData []byte) (*http.Response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "POST", OpenAIModerationURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+key)

	return p.client.Do(httpReq)
}

func (p *ToxicityOpenAIPlugin) analyzeModerationResponse(results []ModerationResult) (*types.PluginResponse, error) {
	if len(results) == 0 {
		return nil, fmt.Errorf("no moderation results returned")
	}

	result := results[0]
	var flaggedCategories []string
	for category, score := range result.CategoryScores {
		if threshold, exists := p.config.Thresholds[category]; exists && score >= threshold {
			flaggedCategories = append(flaggedCategories, fmt.Sprintf("%s (%.2f)", category, score))
		}
	}

	if len(flaggedCategories) > 0 {
		return nil, &types.PluginError{
			StatusCode: http.StatusForbidden,
			Message:    fmt.Sprintf(p.config.Actions.Message+" flagged categories: %v", flaggedCategories),
			Err:        fmt.Errorf("content flagged for categories: %v", flaggedCategories),
		}
	}
	return &types.PluginResponse{StatusCode: 200, Message: "Content is safe"}, nil
}

func (p *ToxicityOpenAIPlugin) raiseEvent(
	collector *metrics.Collector,
	extra ToxicityOpenaiData,
	stage types.Stage,
	error bool,
	errorMessage string,
) {
	evt := metric_events.NewPluginEvent()
	evt.Plugin = &metric_events.PluginDataEvent{
		PluginName:   PluginName,
		Stage:        string(stage),
		Extras:       extra,
		Error:        error,
		ErrorMessage: errorMessage,
	}
	collector.Emit(evt)
}
