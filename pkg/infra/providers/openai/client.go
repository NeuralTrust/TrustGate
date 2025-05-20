package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/valyala/fasthttp"
)

const (
	completionsEndpoint = "https://api.openai.com/v1/chat/completions"
)

type completionRequest struct {
	Model       string     `json:"model"`
	Messages    []messages `json:"messages"`
	MaxTokens   int        `json:"max_tokens,omitempty"`
	Temperature float64    `json:"temperature,omitempty"`
}

type messages struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type client struct {
	httpClient httpx.Client
}

type Response struct {
	ID      string   `json:"id"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

type Choice struct {
	Index   int `json:"index"`
	Message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"message"`
	FinishReason string `json:"finish_reason"`
	Logprobs     struct {
		TokenLogprobs map[string]float64 `json:"token_logprobs"`
	} `json:"logprobs"`
	LogitScores struct{}
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

func NewOpenaiClient(httpClient *fasthttp.Client) providers.Client {
	return &client{
		httpClient: httpx.NewFastHTTPClient(httpClient),
	}
}

func (c *client) Ask(
	ctx context.Context,
	config *providers.Config,
	prompt string,
) (*providers.CompletionResponse, error) {
	if config.Credentials.HeaderValue == "" {
		return nil, fmt.Errorf("API key is required")
	}

	if config.Model == "" {
		return nil, fmt.Errorf("model is required")
	}

	var msgs []messages

	if config.SystemPrompt != "" {
		msgs = append(msgs, messages{
			Role:    "system",
			Content: config.SystemPrompt,
		})
	}
	if len(config.Instructions) > 0 {
		msgs = append(msgs, messages{
			Role:    "developer",
			Content: providers.FormatInstructions(config.Instructions),
		})
	}

	if prompt != "" {
		msgs = append(msgs, messages{
			Role:    "user",
			Content: prompt,
		})
	}

	req := completionRequest{
		Model:       config.Model,
		Messages:    msgs,
		MaxTokens:   config.MaxTokens,
		Temperature: config.Temperature,
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", completionsEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(config.Credentials.HeaderKey, "Bearer "+config.Credentials.HeaderValue)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenAI API returned error (status %d): %s", resp.StatusCode, string(body))
	}

	var completionResp Response
	if err := json.Unmarshal(body, &completionResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if len(completionResp.Choices) == 0 {
		return nil, fmt.Errorf("no completions returned")
	}

	return &providers.CompletionResponse{
		ID:       completionResp.ID,
		Model:    completionResp.Model,
		Response: completionResp.Choices[0].Message.Content,
		Usage: providers.Usage{
			PromptTokens:     completionResp.Usage.PromptTokens,
			CompletionTokens: completionResp.Usage.CompletionTokens,
			TotalTokens:      completionResp.Usage.TotalTokens,
		},
	}, nil
}
