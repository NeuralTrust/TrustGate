package gemini

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"google.golang.org/genai"
)

type geminiStreamRequest struct {
	Model       string        `json:"model"`
	Messages    []interface{} `json:"messages"`
	MaxTokens   int32         `json:"max_tokens"`
	Temperature float64       `json:"temperature"`
	System      string        `json:"system"`
}

type client struct {
	clientPool *sync.Map
}

func NewGeminiClient() providers.Client {
	return &client{
		clientPool: &sync.Map{},
	}
}

func (c *client) Ask(
	ctx context.Context,
	config *providers.Config,
	prompt string,
) (*providers.CompletionResponse, error) {
	if config.Credentials.ApiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}

	if config.Model == "" {
		config.Model = "gemini-pro"
	}

	genaiClient, err := c.getOrCreateClient(ctx, config.Credentials.ApiKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create Gemini client: %w", err)
	}

	var parts []*genai.Part
	if config.SystemPrompt != "" {
		parts = append(parts, &genai.Part{
			Text: config.SystemPrompt,
		})
	}
	if len(config.Instructions) > 0 {
		parts = append(parts, &genai.Part{
			Text: providers.FormatInstructions(config.Instructions),
		})
	}
	var contentConfig *genai.GenerateContentConfig
	if len(parts) > 0 {
		contentConfig = &genai.GenerateContentConfig{
			SystemInstruction: &genai.Content{
				Parts: parts,
				Role:  "system",
			},
		}
	}

	result, err := genaiClient.Models.GenerateContent(
		ctx,
		config.Model,
		genai.Text(prompt),
		contentConfig,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate content: %w", err)
	}

	responseText := result.Text()
	responseText = strings.TrimPrefix(responseText, "```json")
	responseText = strings.TrimSuffix(responseText, "```")
	responseText = strings.TrimSpace(responseText)

	completionResp := &providers.CompletionResponse{
		ID:       result.ResponseID,
		Model:    config.Model,
		Response: responseText,
	}

	completionResp.Usage = providers.Usage{
		PromptTokens:     int(result.UsageMetadata.PromptTokenCount),
		CompletionTokens: int(result.UsageMetadata.CandidatesTokenCount),
		TotalTokens:      int(result.UsageMetadata.TotalTokenCount),
	}

	if responseText == "" {
		return nil, fmt.Errorf("no completions returned")
	}

	return completionResp, nil
}

func (c *client) parseRequest(reqBody []byte, config *providers.Config) (geminiStreamRequest, string, *genai.GenerateContentConfig, error) {
	var req geminiStreamRequest
	if err := json.Unmarshal(reqBody, &req); err != nil {
		return req, "", nil, fmt.Errorf("invalid request body: %w", err)
	}

	if req.Model == "" {
		req.Model = "gemini-pro"
	}

	if !providers.IsAllowedModel(req.Model, config.AllowedModels) {
		req.Model = config.DefaultModel
	}

	var userContent string
	for _, m := range req.Messages {
		msgMap, ok := m.(map[string]interface{})
		if !ok {
			continue
		}

		role, roleOk := msgMap["role"].(string)
		content, contentOk := msgMap["content"].(string)

		if !roleOk || !contentOk {
			continue
		}

		if role == "user" {
			userContent = content
			break
		}
	}
	var contentConfig *genai.GenerateContentConfig
	if req.System != "" {
		contentConfig = &genai.GenerateContentConfig{
			SystemInstruction: &genai.Content{
				Parts: []*genai.Part{
					{
						Text: req.System,
					},
				},
				Role: "system",
			},
		}
	}

	if req.MaxTokens > 0 {
		if contentConfig == nil {
			contentConfig = &genai.GenerateContentConfig{}
		}
		contentConfig.MaxOutputTokens = req.MaxTokens
	}

	if req.Temperature > 0 {
		if contentConfig == nil {
			contentConfig = &genai.GenerateContentConfig{}
		}
		temp := float32(req.Temperature)
		contentConfig.Temperature = &temp
	}

	return req, userContent, contentConfig, nil
}

func (c *client) Completions(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	if config.Credentials.ApiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}
	genaiClient, err := c.getOrCreateClient(ctx, config.Credentials.ApiKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create Gemini client: %w", err)
	}

	req, userContent, contentConfig, err := c.parseRequest(reqBody, config)
	if err != nil {
		return nil, err
	}

	result, err := genaiClient.Models.GenerateContent(
		ctx,
		req.Model,
		genai.Text(userContent),
		contentConfig,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate content: %w", err)
	}

	if res, err := result.MarshalJSON(); err != nil {
		return nil, fmt.Errorf("failed to marshal gemini response: %w", err)
	} else {
		return res, nil
	}
}

func (c *client) CompletionsStream(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
	streamChan chan []byte,
	breakChan chan struct{},
) error {
	if config.Credentials.ApiKey == "" {
		return fmt.Errorf("API key is required")
	}
	genaiClient, err := c.getOrCreateClient(ctx, config.Credentials.ApiKey)
	if err != nil {
		return fmt.Errorf("failed to create Gemini client: %w", err)
	}

	req, userContent, contentConfig, err := c.parseRequest(reqBody, config)
	if err != nil {
		return err
	}

	stream := genaiClient.Models.GenerateContentStream(ctx, req.Model, genai.Text(userContent), contentConfig)

	for obj, err := range stream {
		if err != nil {
			return fmt.Errorf("failed to stream: %w", err)
		}
		close(breakChan)
		if obj == nil {
			continue
		}

		text := obj.Text()
		if text == "" {
			continue
		}

		msg := map[string]string{"content": text}
		b, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("failed to marshal response: %w", err)
		}

		streamChan <- b
	}

	return nil
}

func (c *client) getOrCreateClient(ctx context.Context, apiKey string) (*genai.Client, error) {
	if clientVal, ok := c.clientPool.Load(apiKey); ok {
		client, ok := clientVal.(*genai.Client)
		if !ok {
			return nil, fmt.Errorf("invalid client type in pool")
		}
		return client, nil
	}
	genaiClient, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey:  apiKey,
		Backend: genai.BackendGeminiAPI,
	})
	if err != nil {
		return nil, err
	}
	c.clientPool.Store(apiKey, genaiClient)
	return genaiClient, nil
}
