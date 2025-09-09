package openai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/mitchellh/mapstructure"
	"github.com/openai/openai-go/v2"
	"github.com/openai/openai-go/v2/option"
	"golang.org/x/sync/singleflight"
)

const (
	httpClientTimeout = 120
	CompletionsAPI    = "completions"
	ResponsesAPI      = "responses"
	responsesURL      = "https://api.openai.com/v1/responses"
)

type openaiStreamRequest struct {
	Model       string                         `json:"model"`
	Messages    []openai.ChatCompletionMessage `json:"messages"`
	MaxTokens   int                            `json:"max_tokens"`
	Temperature float64                        `json:"temperature"`
	System      string                         `json:"system"`
}

type openaiOptions struct {
	API string `json:"api"`
}

type client struct {
	clientPool     *sync.Map
	httpClientPool *sync.Map
	sf             singleflight.Group
}

func NewOpenaiClient() providers.Client {
	return &client{
		clientPool:     &sync.Map{},
		httpClientPool: &sync.Map{},
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
	var options openaiOptions
	if len(config.Options) > 0 {
		err := mapstructure.Decode(config.Options, &options)
		if err != nil {
			options = openaiOptions{API: CompletionsAPI}
		}
	} else {
		options = openaiOptions{API: CompletionsAPI}
	}

	if config.Credentials.ApiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}
	openaiClient := c.getOrCreateClient(config.Credentials.ApiKey)

	switch options.API {
	case CompletionsAPI:
		return c.handleCompletionsAPI(ctx, openaiClient, reqBody, config)
	case ResponsesAPI:
		return c.handleResponsesAPI(ctx, reqBody, config)
	default:
		return nil, fmt.Errorf("unsupported API type: %s", options.API)
	}
}

func (c *client) CompletionsStream(
	req *types.RequestContext,
	config *providers.Config,
	reqBody []byte,
	streamChan chan []byte,
	breakChan chan struct{},
) error {
	if config.Credentials.ApiKey == "" {
		return fmt.Errorf("API key is required")
	}

	var options openaiOptions
	if len(config.Options) > 0 {
		if err := mapstructure.Decode(config.Options, &options); err != nil {
			options = openaiOptions{API: CompletionsAPI}
		}
	} else {
		options = openaiOptions{API: CompletionsAPI}
	}

	switch options.API {
	case ResponsesAPI:
		return c.handleResponsesStreamAPI(req, config, reqBody, streamChan, breakChan)
	case CompletionsAPI:
		fallthrough
	default:
		return c.handleCompletionsStreamAPI(req, config, reqBody, streamChan, breakChan)
	}
}

func (c *client) handleCompletionsStreamAPI(
	req *types.RequestContext,
	config *providers.Config,
	reqBody []byte,
	streamChan chan []byte,
	breakChan chan struct{},
) error {
	openaiClient := c.getOrCreateClient(config.Credentials.ApiKey)
	params, err := c.generateParams(reqBody, config)
	if err != nil {
		return err
	}
	respStream := openaiClient.Chat.Completions.NewStreaming(req.C.Context(), params)
	defer respStream.Close()
	if err := respStream.Err(); err != nil {
		return err
	}
	close(breakChan)
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
	return nil
}

func (c *client) handleResponsesStreamAPI(
	req *types.RequestContext,
	config *providers.Config,
	reqBody []byte,
	streamChan chan []byte,
	breakChan chan struct{},
) error {
	httpClient := c.getOrCreateHTTPClient()

	httpReq, err := http.NewRequestWithContext(req.C.Context(), http.MethodPost, responsesURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+config.Credentials.ApiKey)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var preview bytes.Buffer
		_, _ = io.CopyN(&preview, resp.Body, 64*1024)
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, preview.String())
	}

	for key, values := range resp.Header {
		for _, v := range values {
			req.C.Set(key, v)
		}
	}

	select {
	case <-req.C.Context().Done():
		return req.C.Context().Err()
	case <-time.After(0):
	}
	close(breakChan)

	return c.streamSSE(req.C.Context(), resp.Body, streamChan)
}

func (c *client) streamSSE(ctx context.Context, r io.Reader, out chan []byte) error {
	sc := bufio.NewScanner(r)
	buf := make([]byte, 0, 512*1024)
	sc.Buffer(buf, 2*1024*1024)

	for sc.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := sc.Text()
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))

		if data == "[DONE]" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- []byte(line):
		}
	}

	if err := sc.Err(); err != nil {
		if errors.Is(err, io.EOF) ||
			strings.Contains(strings.ToLower(err.Error()), "use of closed network connection") ||
			strings.Contains(strings.ToLower(err.Error()), "connection reset by peer") {
			return nil
		}
		return fmt.Errorf("sse scanner error: %w", err)
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

func (c *client) handleCompletionsAPI(
	ctx context.Context,
	openaiClient *openai.Client,
	reqBody []byte,
	config *providers.Config,
) ([]byte, error) {
	params, err := c.generateParams(reqBody, config)
	if err != nil {
		return nil, err
	}
	resp, err := openaiClient.Chat.Completions.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("openAI completions request failed: %w", err)
	}
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("no completions returned")
	}
	return []byte(resp.RawJSON()), nil
}

func (c *client) handleResponsesAPI(
	ctx context.Context,
	reqBody []byte,
	config *providers.Config,
) ([]byte, error) {
	httpClient := c.getOrCreateHTTPClient()
	responseBody, err := c.callResponsesAPI(
		ctx,
		httpClient,
		config.Credentials.ApiKey,
		reqBody,
	)
	if err != nil {
		return nil, fmt.Errorf("openAI responses request failed: %w", err)
	}
	return responseBody, nil
}

func (c *client) getOrCreateClient(apiKey string) *openai.Client {
	if v, ok := c.clientPool.Load(apiKey); ok {
		if client, ok := v.(*openai.Client); ok {
			return client
		}
	}
	v, err, _ := c.sf.Do(apiKey, func() (any, error) {
		if v2, ok := c.clientPool.Load(apiKey); ok {
			return v2, nil
		}
		cli := openai.NewClient(option.WithAPIKey(apiKey))
		c.clientPool.Store(apiKey, &cli)
		return &cli, nil
	})
	if err != nil {
		cli := openai.NewClient(option.WithAPIKey(apiKey))
		return &cli
	}
	if client, ok := v.(*openai.Client); ok {
		return client
	}
	cli := openai.NewClient(option.WithAPIKey(apiKey))
	return &cli
}

func (c *client) getOrCreateHTTPClient() *http.Client {
	const clientKey = "default"
	if v, ok := c.httpClientPool.Load(clientKey); ok {
		if client, ok := v.(*http.Client); ok {
			return client
		}
	}
	v, err, _ := c.sf.Do(clientKey, func() (any, error) {
		if v2, ok := c.httpClientPool.Load(clientKey); ok {
			return v2, nil
		}
		httpClient := &http.Client{
			Timeout: httpClientTimeout * time.Second,
		}
		c.httpClientPool.Store(clientKey, httpClient)
		return httpClient, nil
	})
	if err != nil {
		return &http.Client{
			Timeout: httpClientTimeout * time.Second,
		}
	}
	if client, ok := v.(*http.Client); ok {
		return client
	}
	return &http.Client{
		Timeout: httpClientTimeout * time.Second,
	}
}

func (c *client) callResponsesAPI(
	ctx context.Context,
	httpClient *http.Client,
	apiKey string,
	reqBody []byte,
) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(
		ctx,
		"POST",
		responsesURL,
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	var responseBody bytes.Buffer
	if _, err := responseBody.ReadFrom(resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, responseBody.String())
	}

	return responseBody.Bytes(), nil
}
