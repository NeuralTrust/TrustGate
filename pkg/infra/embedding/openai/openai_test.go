package openai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/valyala/fasthttp"
)

// mockFastHTTPClient is a mock for fasthttp.Client
type mockFastHTTPClient struct {
	mock.Mock
}

// DoTimeout mocks the DoTimeout method of fasthttp.Client
func (m *mockFastHTTPClient) DoTimeout(req *fasthttp.Request, resp *fasthttp.Response, timeout time.Duration) error {
	args := m.Called(req, resp, timeout)

	// If there's a response body to set
	if len(args) > 1 && args.Get(1) != nil {
		if body, ok := args.Get(1).([]byte); ok {
			resp.SetBody(body)
		}
	}

	// If there's a status code to set
	if len(args) > 2 && args.Get(2) != nil {
		if statusCode, ok := args.Get(2).(int); ok {
			resp.SetStatusCode(statusCode)
		}
	}

	return args.Error(0)
}

// testEmbeddingService is a test-specific version of embeddingService
type testEmbeddingService struct {
	mockClient *mockFastHTTPClient
	logger     *logrus.Logger
}

// newTestEmbeddingService creates a new test embedding service with a mock client
func newTestEmbeddingService() (*testEmbeddingService, *mockFastHTTPClient) {
	mockClient := new(mockFastHTTPClient)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs during test

	return &testEmbeddingService{
		mockClient: mockClient,
		logger:     logger,
	}, mockClient
}

// Generate implements the embedding.Creator interface for testing
func (s *testEmbeddingService) Generate(
	ctx context.Context,
	text, model string,
	upstreamEmbedding *embedding.Config,
) (*embedding.Embedding, error) {
	var emptyData *embedding.Embedding = nil

	if upstreamEmbedding.Credentials.ApiKey == "" {
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

	if err := ctx.Err(); err != nil {
		return emptyData, err
	}

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

	req.SetRequestURI(openAIEmbeddingsURL)
	req.Header.SetMethod("POST")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", upstreamEmbedding.Credentials.ApiKey))
	req.SetBody(pBytes)

	err = s.mockClient.DoTimeout(req, resp, defaultRequestTimeout)
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
		}).Debug("Post-normalization vector stats")
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

func TestNewOpenAIEmbeddingService(t *testing.T) {
	client := &fasthttp.Client{}
	logger := logrus.New()

	service := NewOpenAIEmbeddingService(client, logger)

	assert.NotNil(t, service, "Service should not be nil")
	assert.Implements(t, (*embedding.Creator)(nil), service, "Service should implement embedding.Creator")
}

func TestGenerate_DefaultEmbedding(t *testing.T) {
	service, mockClient := newTestEmbeddingService()

	// Test with empty API key
	config := &embedding.Config{
		Provider: "openai",
		Model:    "text-embedding-ada-002",
		Credentials: domain.CredentialsJSON{
			ApiKey: "", // Empty API key
		},
	}

	emb, err := service.Generate(context.Background(), "test text", "text-embedding-ada-002", config)

	assert.NoError(t, err, "Should not return an error")
	assert.NotNil(t, emb, "Embedding should not be nil")
	assert.Len(t, emb.Value, vectorDimension, "Embedding should have correct dimension")

	// All values should be 1.0
	for _, val := range emb.Value {
		assert.Equal(t, 1.0, val, "Default embedding values should be 1.0")
	}

	// Verify that no HTTP request was made
	mockClient.AssertNotCalled(t, "DoTimeout")
}

func TestGenerate_SuccessfulRequest(t *testing.T) {
	service, mockClient := newTestEmbeddingService()

	// Create a sample response
	responseData := map[string]interface{}{
		"data": []map[string]interface{}{
			{
				"embedding": generateTestEmbedding(vectorDimension),
				"index":     0,
			},
		},
	}
	responseBody, _ := json.Marshal(responseData) //nolint:errcheck

	// Set up the mock to return a successful response
	mockClient.On("DoTimeout", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, responseBody, fasthttp.StatusOK)

	config := &embedding.Config{
		Provider: "openai",
		Model:    "text-embedding-ada-002",
		Credentials: domain.CredentialsJSON{
			ApiKey: "test-api-key",
		},
	}

	emb, err := service.Generate(context.Background(), "test text", "text-embedding-ada-002", config)

	assert.NoError(t, err, "Should not return an error")
	assert.NotNil(t, emb, "Embedding should not be nil")
	assert.Len(t, emb.Value, vectorDimension, "Embedding should have correct dimension")

	// Verify that the HTTP request was made
	mockClient.AssertCalled(t, "DoTimeout", mock.Anything, mock.Anything, 30*time.Second)

	// Verify that the embedding was normalized (sum of squares should be close to 1)
	var sumSquares float64
	for _, val := range emb.Value {
		sumSquares += val * val
	}
	assert.InDelta(t, 1.0, sumSquares, 1e-6, "Embedding should be normalized to unit length")
}

func TestGenerate_HTTPError(t *testing.T) {
	service, mockClient := newTestEmbeddingService()

	// Set up the mock to return an error
	mockClient.On("DoTimeout", mock.Anything, mock.Anything, mock.Anything).
		Return(errors.New("HTTP request failed"), nil, 0)

	config := &embedding.Config{
		Provider: "openai",
		Model:    "text-embedding-ada-002",
		Credentials: domain.CredentialsJSON{
			ApiKey: "test-api-key",
		},
	}

	emb, err := service.Generate(context.Background(), "test text", "text-embedding-ada-002", config)

	assert.Error(t, err, "Should return an error")
	assert.Nil(t, emb, "Embedding should be nil")
	assert.Contains(t, err.Error(), "HTTP request failed", "Error message should contain the HTTP error")

	// Verify that the HTTP request was made
	mockClient.AssertCalled(t, "DoTimeout", mock.Anything, mock.Anything, 30*time.Second)
}

func TestGenerate_NonOKResponse(t *testing.T) {
	service, mockClient := newTestEmbeddingService()

	// Set up the mock to return a non-OK response
	mockClient.On("DoTimeout", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, []byte("Error message"), fasthttp.StatusBadRequest)

	config := &embedding.Config{
		Provider: "openai",
		Model:    "text-embedding-ada-002",
		Credentials: domain.CredentialsJSON{
			ApiKey: "test-api-key",
		},
	}

	emb, err := service.Generate(context.Background(), "test text", "text-embedding-ada-002", config)

	assert.Error(t, err, "Should return an error")
	assert.Nil(t, emb, "Embedding should be nil")
	assert.Contains(t, err.Error(), "non-OK status", "Error message should mention non-OK status")

	// Verify that the HTTP request was made
	mockClient.AssertCalled(t, "DoTimeout", mock.Anything, mock.Anything, 30*time.Second)
}

func TestGenerate_InvalidResponseFormat(t *testing.T) {
	service, mockClient := newTestEmbeddingService()

	// Set up the mock to return an invalid JSON response
	mockClient.On("DoTimeout", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, []byte("invalid json"), fasthttp.StatusOK)

	config := &embedding.Config{
		Provider: "openai",
		Model:    "text-embedding-ada-002",
		Credentials: domain.CredentialsJSON{
			ApiKey: "test-api-key",
		},
	}

	emb, err := service.Generate(context.Background(), "test text", "text-embedding-ada-002", config)

	assert.Error(t, err, "Should return an error")
	assert.Nil(t, emb, "Embedding should be nil")

	// Verify that the HTTP request was made
	mockClient.AssertCalled(t, "DoTimeout", mock.Anything, mock.Anything, 30*time.Second)
}

func TestGenerate_EmptyEmbeddings(t *testing.T) {
	service, mockClient := newTestEmbeddingService()

	// Create a sample response with empty embeddings
	responseData := map[string]interface{}{
		"data": []map[string]interface{}{},
	}
	responseBody, _ := json.Marshal(responseData) //nolint:errcheck

	// Set up the mock to return a response with empty embeddings
	mockClient.On("DoTimeout", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, responseBody, fasthttp.StatusOK)

	config := &embedding.Config{
		Provider: "openai",
		Model:    "text-embedding-ada-002",
		Credentials: domain.CredentialsJSON{
			ApiKey: "test-api-key",
		},
	}

	emb, err := service.Generate(context.Background(), "test text", "text-embedding-ada-002", config)

	assert.Error(t, err, "Should return an error")
	assert.Nil(t, emb, "Embedding should be nil")
	assert.Contains(t, err.Error(), "empty embeddings", "Error message should mention empty embeddings")

	// Verify that the HTTP request was made
	mockClient.AssertCalled(t, "DoTimeout", mock.Anything, mock.Anything, 30*time.Second)
}

func TestGenerate_ZeroNorm(t *testing.T) {
	service, mockClient := newTestEmbeddingService()

	// Create a sample response with all zeros
	zeroEmbedding := make([]float64, vectorDimension)
	responseData := map[string]interface{}{
		"data": []map[string]interface{}{
			{
				"embedding": zeroEmbedding,
				"index":     0,
			},
		},
	}
	responseBody, _ := json.Marshal(responseData) //nolint:errcheck

	// Set up the mock to return a response with zero embeddings
	mockClient.On("DoTimeout", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, responseBody, fasthttp.StatusOK)

	config := &embedding.Config{
		Provider: "openai",
		Model:    "text-embedding-ada-002",
		Credentials: domain.CredentialsJSON{
			ApiKey: "test-api-key",
		},
	}

	emb, err := service.Generate(context.Background(), "test text", "text-embedding-ada-002", config)

	assert.NoError(t, err, "Should not return an error")
	assert.NotNil(t, emb, "Embedding should not be nil")
	assert.Len(t, emb.Value, vectorDimension, "Embedding should have correct dimension")

	// All values should be zero
	for _, val := range emb.Value {
		assert.Equal(t, 0.0, val, "Embedding values should be 0.0")
	}

	// Verify that the HTTP request was made
	mockClient.AssertCalled(t, "DoTimeout", mock.Anything, mock.Anything, 30*time.Second)
}

// Helper function to generate a test embedding
func generateTestEmbedding(size int) []float64 {
	embedding := make([]float64, size)
	for i := 0; i < size; i++ {
		embedding[i] = float64(i) / float64(size) // Simple pattern
	}
	return embedding
}
