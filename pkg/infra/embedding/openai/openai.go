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
	vectorDimension = 1536
)

type embeddingService struct {
	client *fasthttp.Client
	logger *logrus.Logger
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
	var emptyData *embedding.Embedding = nil

	if upstreamEmbedding.Credentials.HeaderValue == "" {
		s.logger.Warn("embeddings API key not provided, using default embedding")
		val := make([]float64, vectorDimension)
		for i := 0; i < vectorDimension; i++ {
			val[i] = 1.0
		}
		return &embedding.Embedding{
			Value:     val,
			CreatedAt: time.Now(),
		}, nil
	}

	url := "https://api.openai.com/v1/embeddings"

	requestPayload := map[string]interface{}{
		"model": model,
		"input": text,
	}
	pBytes, err := json.Marshal(requestPayload)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal embedding request payload")
		return emptyData, err
	}

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(url)
	req.Header.SetMethod("POST")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", upstreamEmbedding.Credentials.HeaderValue)
	req.SetBody(pBytes)

	err = s.client.DoTimeout(req, resp, 30*time.Second)
	if err != nil {
		s.logger.WithError(err).Error("Error performing HTTP request for embeddings")
		return emptyData, err
	}

	statusCode := resp.StatusCode()
	if statusCode != fasthttp.StatusOK {
		respBody := resp.Body()
		s.logger.WithField("response", string(respBody)).Error("Non-OK response from embeddings API")
		return emptyData, fmt.Errorf("non-OK status from embeddings API: %d", statusCode)
	}

	// Define structure for the OpenAI embeddings response
	type OpenAIEmbeddingResponse struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
			Index     int       `json:"index"`
		} `json:"data"`
	}

	var embResp OpenAIEmbeddingResponse
	if err := json.Unmarshal(resp.Body(), &embResp); err != nil {
		s.logger.WithError(err).Error("Failed to decode embeddings response")
		return emptyData, err
	}

	if len(embResp.Data) == 0 || len(embResp.Data[0].Embedding) == 0 {
		s.logger.Error("Empty embeddings received from API")
		return emptyData, fmt.Errorf("empty embeddings from API")
	}

	// Get the embedding from the response
	rawEmbedding := embResp.Data[0].Embedding
	s.logger.Debugf("Generated embedding sample (first 5 values): %v", rawEmbedding[:min(5, len(rawEmbedding))])

	// Normalize the embedding to unit length
	var sumSquares = 0.0
	for _, val := range rawEmbedding {
		sumSquares += val * val
	}
	norm := math.Sqrt(sumSquares)

	s.logger.WithFields(logrus.Fields{
		"pre_norm":        norm,
		"pre_norm_sample": rawEmbedding[:min(5, len(rawEmbedding))],
	}).Debug("Pre-normalization vector stats")

	if norm > 0 {
		for i := range rawEmbedding {
			rawEmbedding[i] /= norm
		}
		// Verify normalization
		sumSquares = 0.0
		for _, val := range rawEmbedding {
			sumSquares += val * val
		}
		postNorm := math.Sqrt(sumSquares)

		s.logger.WithFields(logrus.Fields{
			"post_norm":        postNorm,
			"post_norm_sample": rawEmbedding[:min(5, len(rawEmbedding))],
			"is_unit_vector":   math.Abs(postNorm-1.0) < 1e-6,
		}).Debug("post-normalization vector stats")
	} else {
		s.logger.Warn("Zero norm encountered during embedding normalization")
	}
	s.logger.Debugf("Normalized embedding sample (first 5 values): %v", rawEmbedding[:min(5, len(rawEmbedding))])

	if len(rawEmbedding) != vectorDimension {
		s.logger.Warnf("Generated embedding size %d does not match expected vector dimension %d", len(rawEmbedding), vectorDimension)
	}

	return &embedding.Embedding{
		Value:     rawEmbedding,
		CreatedAt: time.Now(),
	}, nil
}
