package toxicity_openai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
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
	evtCtx *metrics.EventContext,
) (*types.PluginResponse, error) {
	var conf Config
	if err := mapstructure.Decode(cfg.Settings, &conf); err != nil {
		p.logger.WithError(err).Error("Failed to decode config")
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	var requestBody RequestBody
	if err := json.Unmarshal(req.Body, &requestBody); err != nil {
		return nil, fmt.Errorf("failed to parse request body: %w", err)
	}

	moderationInputs := p.extractModerationInputs(requestBody.Messages)
	if len(moderationInputs) == 0 {
		return &types.PluginResponse{StatusCode: 200, Message: "No content to moderate"}, nil
	}

	// Calculate input length
	inputLength := 0
	for _, input := range moderationInputs {
		inputLength += len(input.Text)
	}

	moderationReq := OpenAIModerationRequest{Input: moderationInputs, Model: "omni-moderation-latest"}
	jsonData, err := json.Marshal(moderationReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal moderation request: %w", err)
	}

	startTime := time.Now()
	httpResp, err := p.sendModerationRequest(ctx, conf.OpenAIKey, jsonData)
	latencyMs := time.Since(startTime).Milliseconds()

	if err != nil {
		return nil, err
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenAI API returned error: %s", string(body))
	}

	var moderationResp OpenAIModerationResponse
	if err := json.Unmarshal(body, &moderationResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal moderation response: %w", err)
	}

	return p.analyzeModerationResponse(conf, moderationResp, evtCtx, inputLength, len(moderationInputs), latencyMs)
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

func (p *ToxicityOpenAIPlugin) analyzeModerationResponse(
	conf Config,
	moderationResp OpenAIModerationResponse,
	evtCtx *metrics.EventContext,
	inputLength int,
	inputCount int,
	latencyMs int64,
) (*types.PluginResponse, error) {
	if len(moderationResp.Results) == 0 {
		return nil, fmt.Errorf("no moderation results returned")
	}

	result := moderationResp.Results[0]

	// Find max score and category
	var maxScore float64
	var maxCategory string
	for category, score := range result.CategoryScores {
		if score > maxScore {
			maxScore = score
			maxCategory = category
		}
	}

	evt := &ToxicityOpenaiData{
		Model:       moderationResp.Model,
		InputLength: inputLength,
		InputCount:  inputCount,
		Blocked:     false,
		Scores: &ToxicityScores{
			CategoryScores:   result.CategoryScores,
			FlaggedByOpenAI:  result.Flagged,
			MaxScore:         maxScore,
			MaxScoreCategory: maxCategory,
		},
		DetectionLatencyMs: latencyMs,
	}

	var flaggedCategories []FlaggedCategory
	for category, score := range result.CategoryScores {
		if threshold, exists := conf.Thresholds[category]; exists && score >= threshold {
			flaggedCategories = append(flaggedCategories, FlaggedCategory{
				Category:  category,
				Score:     score,
				Threshold: threshold,
			})
		}
	}

	if len(flaggedCategories) > 0 {
		evt.Blocked = true
		categoryNames := make([]string, len(flaggedCategories))
		for i, fc := range flaggedCategories {
			categoryNames[i] = fmt.Sprintf("%s (%.2f)", fc.Category, fc.Score)
		}
		violationMsg := fmt.Sprintf("content flagged for categories: %v", categoryNames)

		evt.Violation = &ViolationInfo{
			FlaggedCategories: flaggedCategories,
			Message:           violationMsg,
		}

		evtCtx.SetError(errors.New(violationMsg))
		evtCtx.SetExtras(evt)
		return nil, &types.PluginError{
			StatusCode: http.StatusForbidden,
			Message:    conf.Actions.Message + " " + violationMsg,
			Err:        errors.New(violationMsg),
		}
	}

	evtCtx.SetExtras(evt)
	return &types.PluginResponse{StatusCode: 200, Message: "Content is safe"}, nil
}
