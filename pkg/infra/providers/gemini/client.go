package gemini

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"google.golang.org/genai"
)

type geminiStreamRequest struct {
	Model             string                       `json:"model"`
	Messages          []interface{}                `json:"messages,omitempty"`
	Contents          []*genai.Content             `json:"contents,omitempty"`
	SystemInstruction *genai.Content               `json:"systemInstruction,omitempty"`
	GenerationConfig  *genai.GenerateContentConfig `json:"generationConfig,omitempty"`
	MaxTokens         int32                        `json:"max_tokens,omitempty"`
	Temperature       float64                      `json:"temperature,omitempty"`
	System            string                       `json:"system,omitempty"`
	Tools             []*genai.Tool                `json:"tools,omitempty"`
	ToolConfig        *genai.ToolConfig            `json:"toolConfig,omitempty"`
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
	temperature := float32(0.0)
	if config.Temperature > 0 {
		temperature = float32(config.Temperature)
	}

	if len(parts) > 0 {
		topP := float32(1.0)
		contentConfig = &genai.GenerateContentConfig{
			Temperature: &temperature,
			TopP:        &topP,
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

	req, contents, contentConfig, err := c.parseRequest(reqBody, config)
	if err != nil {
		return nil, err
	}

	result, err := genaiClient.Models.GenerateContent(
		ctx,
		req.Model,
		contents,
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
	reqCtx *types.RequestContext,
	config *providers.Config,
	reqBody []byte,
	streamChan chan []byte,
	breakChan chan struct{},
) error {
	if config.Credentials.ApiKey == "" {
		return fmt.Errorf("API key is required")
	}
	genaiClient, err := c.getOrCreateClient(reqCtx.C.Context(), config.Credentials.ApiKey)
	if err != nil {
		return fmt.Errorf("failed to create Gemini client: %w", err)
	}

	req, contents, contentConfig, err := c.parseRequest(reqBody, config)
	if err != nil {
		return err
	}

	stream := genaiClient.Models.GenerateContentStream(reqCtx.C.Context(), req.Model, contents, contentConfig)
	times := 0
	for obj, err := range stream {
		if err != nil {
			return fmt.Errorf("failed to stream: %w", err)
		} else {
			if times == 0 {
				close(breakChan)
			}
		}
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
		times++
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

func (c *client) parseRequest(
	reqBody []byte,
	config *providers.Config,
) (geminiStreamRequest, []*genai.Content, *genai.GenerateContentConfig, error) {
	var req geminiStreamRequest
	if err := json.Unmarshal(reqBody, &req); err != nil {
		return req, nil, nil, fmt.Errorf("invalid request body: %w", err)
	}

	if req.Model == "" {
		req.Model = "gemini-pro"
	}

	if !providers.IsAllowedModel(req.Model, config.AllowedModels) {
		req.Model = config.DefaultModel
	}

	var contents []*genai.Content

	if len(req.Contents) > 0 {
		contents = req.Contents
	} else if len(req.Messages) > 0 {
		for _, m := range req.Messages {
			msgMap, ok := m.(map[string]interface{})
			if !ok {
				continue
			}

			role := "user"
			if r, ok := msgMap["role"].(string); ok && r != "" {
				role = r
			}
			var parts []*genai.Part

			if contentVal, ok := msgMap["content"]; ok {
				switch v := contentVal.(type) {
				case string:
					parts = append(parts, &genai.Part{Text: v})
				case []interface{}:
					for _, part := range v {
						partBytes, err := json.Marshal(part)
						if err != nil {
							return req, nil, nil, fmt.Errorf("failed to marshal part: %w", err)
						}
						var genPart genai.Part
						if err := json.Unmarshal(partBytes, &genPart); err != nil {
							return req, nil, nil, fmt.Errorf("failed to unmarshal part: %w", err)
						}
						parts = append(parts, &genPart)
					}
				case map[string]interface{}:
					partBytes, err := json.Marshal(v)
					if err != nil {
						return req, nil, nil, fmt.Errorf("failed to marshal part: %w", err)
					}
					var genPart genai.Part
					if err := json.Unmarshal(partBytes, &genPart); err != nil {
						return req, nil, nil, fmt.Errorf("failed to unmarshal part: %w", err)
					}
					parts = append(parts, &genPart)
				}
			}

			if len(parts) == 0 {
				continue
			}

			contents = append(contents, &genai.Content{
				Role:  role,
				Parts: parts,
			})
		}
	}

	if len(contents) == 0 {
		return req, nil, nil, fmt.Errorf("no user content provided")
	}

	var genConfig *genai.GenerateContentConfig
	if req.GenerationConfig != nil {
		copyConfig := *req.GenerationConfig
		genConfig = &copyConfig
	}

	if req.SystemInstruction != nil {
		if genConfig == nil {
			genConfig = &genai.GenerateContentConfig{}
		}
		genConfig.SystemInstruction = req.SystemInstruction
	} else if req.System != "" {
		if genConfig == nil {
			genConfig = &genai.GenerateContentConfig{}
		}
		genConfig.SystemInstruction = &genai.Content{
			Role:  "system",
			Parts: []*genai.Part{{Text: req.System}},
		}

	}

	if req.MaxTokens > 0 {
		if genConfig == nil {
			genConfig = &genai.GenerateContentConfig{}
		}
		genConfig.MaxOutputTokens = req.MaxTokens
	}

	if req.Temperature > 0 {
		if genConfig == nil {
			genConfig = &genai.GenerateContentConfig{}
		}
		temp := float32(req.Temperature)
		genConfig.Temperature = &temp
	}

	if len(req.Tools) > 0 {
		if genConfig == nil {
			genConfig = &genai.GenerateContentConfig{}
		}
		genConfig.Tools = req.Tools
	}

	if req.ToolConfig != nil {
		if genConfig == nil {
			genConfig = &genai.GenerateContentConfig{}
		}
		genConfig.ToolConfig = req.ToolConfig
	}

	return req, contents, genConfig, nil
}
