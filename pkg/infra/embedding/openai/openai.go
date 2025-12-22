package openai

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

const (
	vectorDimension       = 1536
	openAIEmbeddingsURL   = "https://api.openai.com/v1/embeddings"
	defaultRequestTimeout = 30 * time.Second
)

type embeddingService struct {
	client *fasthttp.Client
	logger *logrus.Logger
}

type embeddingRequest struct {
	Model string `json:"model"`
	Input string `json:"input"`
}

type embeddingData struct {
	Embedding []float64 `json:"embedding"`
	Index     int       `json:"index"`
}

type openAIEmbeddingResponse struct {
	Data []embeddingData `json:"data"`
}

func NewOpenAIEmbeddingService(client *fasthttp.Client, logger *logrus.Logger) embedding.Creator {
	return &embeddingService{
		client: client,
		logger: logger,
	}
}

func (s *embeddingService) Generate(
	ctx context.Context,
	text, model string,
	upstreamEmbedding *embedding.Config,
) (*embedding.Embedding, error) {
	if upstreamEmbedding.Credentials.ApiKey == "" {
		s.logger.Warn("embeddings API key not provided, using default embedding")
		return s.createDefaultEmbedding(), nil
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	pBytes, err := json.Marshal(embeddingRequest{
		Model: model,
		Input: text,
	})
	if err != nil {
		s.logger.WithError(err).Error("failed to marshal embedding request payload")
		return nil, err
	}

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(openAIEmbeddingsURL)
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.SetContentType("application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", upstreamEmbedding.Credentials.ApiKey))
	req.SetBody(pBytes)

	if err := s.doRequestWithContext(ctx, req, resp); err != nil {
		return nil, err
	}

	if resp.StatusCode() != fasthttp.StatusOK {
		s.logger.WithField("response", string(resp.Body())).Error("non-OK response from embeddings API")
		return nil, fmt.Errorf("%w: %d", embedding.ErrProviderNonOKResponse, resp.StatusCode())
	}

	var embResp openAIEmbeddingResponse
	if err := json.Unmarshal(resp.Body(), &embResp); err != nil {
		s.logger.WithError(err).Error("failed to decode embeddings response")
		return nil, err
	}

	if len(embResp.Data) == 0 || len(embResp.Data[0].Embedding) == 0 {
		s.logger.Error("empty embeddings received from API")
		return nil, fmt.Errorf("empty embeddings from API")
	}

	rawEmbedding := embResp.Data[0].Embedding

	if len(rawEmbedding) != vectorDimension {
		s.logger.Warnf("embedding size %d does not match expected dimension %d", len(rawEmbedding), vectorDimension)
	}

	s.normalizeVector(rawEmbedding)

	return &embedding.Embedding{
		Value:     rawEmbedding,
		CreatedAt: time.Now(),
	}, nil
}

func (s *embeddingService) doRequestWithContext(ctx context.Context, req *fasthttp.Request, resp *fasthttp.Response) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.client.DoTimeout(req, resp, defaultRequestTimeout)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		if err != nil {
			s.logger.WithError(err).Error("error performing HTTP request for embeddings")
		}
		return err
	}
}

func (s *embeddingService) createDefaultEmbedding() *embedding.Embedding {
	val := make([]float64, vectorDimension)
	for i := range val {
		val[i] = 1.0
	}
	return &embedding.Embedding{
		Value:     val,
		CreatedAt: time.Now(),
	}
}

func (s *embeddingService) normalizeVector(v []float64) {
	var sumSquares float64
	for _, val := range v {
		sumSquares += val * val
	}

	norm := math.Sqrt(sumSquares)
	if norm == 0 {
		return
	}

	for i := range v {
		v[i] /= norm
	}
}
