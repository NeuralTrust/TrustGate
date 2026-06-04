package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/embedding"
)

const (
	ProviderName = "openai"

	defaultEmbeddingsURL = "https://api.openai.com/v1/embeddings"
	defaultTimeout       = 30 * time.Second
)

var _ embedding.Creator = (*Creator)(nil)

type Creator struct {
	httpClient *http.Client
	baseURL    string
}

type Option func(*Creator)

func WithHTTPClient(client *http.Client) Option {
	return func(c *Creator) {
		if client != nil {
			c.httpClient = client
		}
	}
}

func WithBaseURL(url string) Option {
	return func(c *Creator) {
		if url != "" {
			c.baseURL = url
		}
	}
}

func NewCreator(opts ...Option) *Creator {
	c := &Creator{
		httpClient: &http.Client{Timeout: defaultTimeout},
		baseURL:    defaultEmbeddingsURL,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type embeddingRequest struct {
	Model string `json:"model"`
	Input string `json:"input"`
}

type embeddingResponse struct {
	Data []struct {
		Embedding []float64 `json:"embedding"`
	} `json:"data"`
}

func (c *Creator) Generate(ctx context.Context, text, model string, cfg *embedding.Config) (*embedding.Embedding, error) {
	if cfg == nil || cfg.Credentials.APIKey == "" {
		return nil, fmt.Errorf("openai embedding: missing api key")
	}

	payload, err := json.Marshal(embeddingRequest{Model: model, Input: text})
	if err != nil {
		return nil, fmt.Errorf("openai embedding: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("openai embedding: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Credentials.APIKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openai embedding: do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openai embedding: %w: %d", embedding.ErrProviderNonOKResponse, resp.StatusCode)
	}

	var decoded embeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("openai embedding: decode response: %w", err)
	}
	if len(decoded.Data) == 0 || len(decoded.Data[0].Embedding) == 0 {
		return nil, fmt.Errorf("openai embedding: empty embedding in response")
	}

	vector := decoded.Data[0].Embedding
	normalize(vector)
	return &embedding.Embedding{Value: vector, CreatedAt: time.Now().UTC()}, nil
}

func normalize(v []float64) {
	var sumSquares float64
	for _, x := range v {
		sumSquares += x * x
	}
	norm := math.Sqrt(sumSquares)
	if norm == 0 {
		return
	}
	for i := range v {
		v[i] /= norm
	}
}
