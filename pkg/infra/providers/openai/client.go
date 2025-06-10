package openai

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
)

type openaiStreamRequest struct {
	Model       string                         `json:"model"`
	Messages    []openai.ChatCompletionMessage `json:"messages"`
	MaxTokens   int                            `json:"max_tokens"`
	Temperature float64                        `json:"temperature"`
	System      string                         `json:"system"`
}

type client struct {
	clientPool *sync.Map
}

func NewOpenaiClient() providers.Client {
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
		return nil, fmt.Errorf("model is required")
	}

	openaiClient := c.getOrCreateClient(config.Credentials.ApiKey)

	var messages []openai.ChatCompletionMessageParamUnion

	if config.SystemPrompt != "" {
		messages = append(messages, openai.SystemMessage(config.SystemPrompt))
	}

	if len(config.Instructions) > 0 {
		messages = append(messages, openai.UserMessage(providers.FormatInstructions(config.Instructions)))
	}

	if prompt != "" {
		messages = append(messages, openai.UserMessage(prompt))
	}

	params := openai.ChatCompletionNewParams{
		Model:    config.Model,
		Messages: messages,
	}

	if config.MaxTokens > 0 {
		params.MaxTokens = openai.Int(int64(config.MaxTokens))
	}

	if config.Temperature > 0 {
		params.Temperature = openai.Float(config.Temperature)
	}

	resp, err := openaiClient.Chat.Completions.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("OpenAI request failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("no completions returned")
	}

	return &providers.CompletionResponse{
		ID:       resp.ID,
		Model:    resp.Model,
		Response: resp.Choices[0].Message.Content,
		Usage: providers.Usage{
			PromptTokens:     int(resp.Usage.PromptTokens),
			CompletionTokens: int(resp.Usage.CompletionTokens),
			TotalTokens:      int(resp.Usage.TotalTokens),
		},
	}, nil
}

func (c *client) Completions(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	if config.Credentials.ApiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}
	openaiClient := c.getOrCreateClient(config.Credentials.ApiKey)
	params, err := c.generateParams(reqBody, config)
	if err != nil {
		return nil, err
	}
	resp, err := openaiClient.Chat.Completions.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("openAI request failed: %w", err)
	}
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("no completions returned")
	}
	return []byte(resp.RawJSON()), nil
}

func (c *client) CompletionsStream(
	ctx context.Context,
	config *providers.Config,
	streamChan chan []byte,
	reqBody []byte,
) error {
	if config.Credentials.ApiKey == "" {
		return fmt.Errorf("API key is required")
	}
	openaiClient := c.getOrCreateClient(config.Credentials.ApiKey)
	params, err := c.generateParams(reqBody, config)
	if err != nil {
		return err
	}

	respStream := openaiClient.Chat.Completions.NewStreaming(ctx, params)
	defer respStream.Close()

	for {
		if !respStream.Next() {
			break
		}
		chunk := respStream.Current()
		for _, choice := range chunk.Choices {
			if content := choice.Delta.Content; content != "" {
				msg := map[string]string{"content": content}
				b, err := json.Marshal(msg)
				if err != nil {
					streamChan <- []byte(fmt.Sprintf(`{"error": "failed to marshal message: %s"}`, err.Error()))
					continue
				}
				streamChan <- b
			}
		}
	}

	if err := respStream.Err(); err != nil {
		return fmt.Errorf("streaming error: %w", err)
	}

	return nil
}

func (c *client) generateParams(reqBody []byte, config *providers.Config) (openai.ChatCompletionNewParams, error) {
	var req openaiStreamRequest
	if err := json.Unmarshal(reqBody, &req); err != nil {
		return openai.ChatCompletionNewParams{}, fmt.Errorf("invalid request body: %w", err)
	}

	if req.Model == "" {
		return openai.ChatCompletionNewParams{}, fmt.Errorf("model is required")
	}

	if !providers.IsAllowedModel(req.Model, config.AllowedModels) {
		req.Model = config.DefaultModel
	}

	var messages []openai.ChatCompletionMessageParamUnion
	for _, m := range req.Messages {
		switch m.Role {
		case "system":
			messages = append(messages, openai.SystemMessage(m.Content))
		case "user":
			messages = append(messages, openai.UserMessage(m.Content))
		case "assistant":
			messages = append(messages, openai.AssistantMessage(m.Content))
		}
	}

	params := openai.ChatCompletionNewParams{
		Model:    req.Model,
		Messages: messages,
	}

	if req.MaxTokens > 0 {
		params.MaxTokens = openai.Int(int64(req.MaxTokens))
	}
	if req.Temperature > 0 {
		params.Temperature = openai.Float(req.Temperature)
	}
	return params, nil
}

func (c *client) getOrCreateClient(apiKey string) openai.Client {
	if clientVal, ok := c.clientPool.Load(apiKey); ok {
		client, ok := clientVal.(openai.Client)
		if !ok {
			// If type assertion fails, create a new client
			client = openai.NewClient(option.WithAPIKey(apiKey))
			c.clientPool.Store(apiKey, client)
		}
		return client
	}
	newClient := openai.NewClient(option.WithAPIKey(apiKey))
	c.clientPool.Store(apiKey, newClient)
	return newClient
}
