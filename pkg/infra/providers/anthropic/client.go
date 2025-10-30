package anthropic

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	pkgTypes "github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

type anthropicStreamRequest struct {
	Model       string        `json:"model"`
	Messages    []interface{} `json:"messages"`
	MaxTokens   int           `json:"max_tokens"`
	Temperature float64       `json:"temperature"`
	System      string        `json:"system"`
	Stream      bool          `json:"stream"`
}

type client struct {
	clientPool *sync.Map
}

func NewAnthropicClient() providers.Client {
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

	anthropicClient := c.getOrCreateClient(config.Credentials.ApiKey)

	var messages []anthropic.MessageParam

	if len(config.Instructions) > 0 {
		messages = append(messages, anthropic.NewUserMessage(
			anthropic.NewTextBlock(providers.FormatInstructions(config.Instructions)),
		))
	}

	if prompt != "" {
		messages = append(messages, anthropic.NewUserMessage(
			anthropic.NewTextBlock(prompt),
		))
	}

	model := anthropic.ModelClaudeHaiku4_5
	if config.Model != "" {
		model = anthropic.Model(config.Model)
	}

	params := anthropic.MessageNewParams{
		Model:     model,
		Messages:  messages,
		MaxTokens: int64(config.MaxTokens),
	}

	if config.SystemPrompt != "" {
		params.System = []anthropic.TextBlockParam{
			{
				Text: config.SystemPrompt,
				Type: "text",
			},
		}
	}

	if config.Temperature > 0 {
		params.Temperature = anthropic.Float(config.Temperature)
	}

	message, err := anthropicClient.Messages.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("anthropic request failed: %w", err)
	}

	if len(message.Content) == 0 {
		return nil, fmt.Errorf("no completions returned")
	}

	var responseText string
	for _, content := range message.Content {
		if content.Type == "text" {
			responseText = content.Text
			break
		}
	}

	if responseText == "" {
		return nil, fmt.Errorf("no text content returned")
	}

	return &providers.CompletionResponse{
		ID:       message.ID,
		Model:    string(model),
		Response: responseText,
		Usage: providers.Usage{
			PromptTokens:     int(message.Usage.InputTokens),
			CompletionTokens: int(message.Usage.OutputTokens),
			TotalTokens:      int(message.Usage.InputTokens + message.Usage.OutputTokens),
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

	anthropicClient := c.getOrCreateClient(config.Credentials.ApiKey)

	params, err := c.getParams(reqBody, config)
	if err != nil {
		return nil, err
	}

	message, err := anthropicClient.Messages.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("anthropic request failed: %w", err)
	}

	return []byte(message.RawJSON()), nil
}

func (c *client) CompletionsStream(
	reqCtx *pkgTypes.RequestContext,
	config *providers.Config,
	reqBody []byte,
	streamChan chan []byte,
	breakChan chan struct{},
) error {
	if config.Credentials.ApiKey == "" {
		return fmt.Errorf("API key is required")
	}
	providerClient := c.getOrCreateClient(config.Credentials.ApiKey)

	params, err := c.getParams(reqBody, config)
	if err != nil {
		return err
	}

	stream := providerClient.Messages.NewStreaming(reqCtx.C.Context(), params)
	defer stream.Close()

	if err := stream.Err(); err != nil {
		return fmt.Errorf("streaming error: %w", err)
	}
	close(breakChan)
	for stream.Next() {
		event := stream.Current()
		if event.Type == "content_block_delta" && event.Delta.Type == "text_delta" {
			if event.Delta.Text != "" {
				msg := map[string]string{"content": event.Delta.Text}
				b, err := json.Marshal(msg)
				if err != nil {
					streamChan <- []byte(fmt.Sprintf(`{"error": "failed to marshal message: %s"}`, err.Error()))
					continue
				}
				streamChan <- b
			}
		}
	}

	return nil
}

func (c *client) getParams(reqBody []byte, config *providers.Config) (anthropic.MessageNewParams, error) {
	var req anthropicStreamRequest
	if err := json.Unmarshal(reqBody, &req); err != nil {
		return anthropic.MessageNewParams{}, fmt.Errorf("invalid request body: %w", err)
	}

	model := anthropic.ModelClaudeHaiku4_5

	if req.Model != "" {
		model = anthropic.Model(req.Model)
	}

	if !providers.IsAllowedModel(req.Model, config.AllowedModels) {
		model = anthropic.Model(config.DefaultModel)
	}

	var anthropicMessages []anthropic.MessageParam
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
		switch role {
		case "user":
			anthropicMessages = append(anthropicMessages, anthropic.NewUserMessage(
				anthropic.NewTextBlock(content),
			))
		case "assistant":
			anthropicMessages = append(anthropicMessages, anthropic.NewAssistantMessage(
				anthropic.NewTextBlock(content),
			))
		case "system":
			if req.System == "" {
				req.System = content
			}
		}
	}

	params := anthropic.MessageNewParams{
		Model:     model,
		Messages:  anthropicMessages,
		MaxTokens: int64(req.MaxTokens),
	}

	if req.System != "" {
		params.System = []anthropic.TextBlockParam{
			{Text: req.System, Type: "text"},
		}
	}

	if req.Temperature > 0 {
		params.Temperature = anthropic.Float(req.Temperature)
	}
	return params, nil
}

func (c *client) getOrCreateClient(apiKey string) anthropic.Client {
	if clientVal, ok := c.clientPool.Load(apiKey); ok {
		client, ok := clientVal.(anthropic.Client)
		if !ok {
			// If type assertion fails, create a new client
			client = anthropic.NewClient(option.WithAPIKey(apiKey))
			c.clientPool.Store(apiKey, client)
		}
		return client
	}
	newClient := anthropic.NewClient(
		option.WithAPIKey(apiKey),
	)
	c.clientPool.Store(apiKey, newClient)
	return newClient
}
