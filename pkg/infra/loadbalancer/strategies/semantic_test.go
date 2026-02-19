package strategies

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	embeddingMocks "github.com/NeuralTrust/TrustGate/pkg/domain/embedding/mocks"
	factoryMocks "github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// --- helpers ---

func makeTargets(descriptions ...string) []types.UpstreamTargetDTO {
	targets := make([]types.UpstreamTargetDTO, len(descriptions))
	for i, desc := range descriptions {
		targets[i] = types.UpstreamTargetDTO{
			ID:          fmt.Sprintf("target-%d", i),
			Host:        fmt.Sprintf("host-%d", i),
			Port:        8080 + i,
			Description: desc,
		}
	}
	return targets
}

func defaultEmbeddingCfg() *types.EmbeddingConfigDTO {
	return &types.EmbeddingConfigDTO{
		Provider: "openai",
		Model:    "text-embedding-3-small",
		Credentials: types.CredentialsDTO{
			ApiKey: "test-key",
		},
	}
}

func makeReqCtx(body string) *types.RequestContext {
	return &types.RequestContext{
		Context: context.Background(),
		Body:    []byte(body),
	}
}

func normalize(v []float64) []float64 {
	var sum float64
	for _, val := range v {
		sum += val * val
	}
	norm := math.Sqrt(sum)
	out := make([]float64, len(v))
	for i, val := range v {
		out[i] = val / norm
	}
	return out
}

func setupSemanticWithRouting(
	t *testing.T,
	targets []types.UpstreamTargetDTO,
	promptEmbedding []float64,
	targetEmbeddings map[string][]float64,
) *Semantic {
	t.Helper()

	repo := embeddingMocks.NewRepository(t)
	for id, vec := range targetEmbeddings {
		repo.EXPECT().GetByTargetID(mock.Anything, id).
			Return(&embedding.Embedding{Value: vec, CreatedAt: time.Now()}, nil)
	}

	creator := embeddingMocks.NewCreator(t)
	creator.EXPECT().Generate(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&embedding.Embedding{Value: promptEmbedding, CreatedAt: time.Now()}, nil)

	locator := factoryMocks.NewEmbeddingServiceLocator(t)
	locator.EXPECT().GetService(mock.Anything).Return(creator, nil)

	return NewSemantic(defaultEmbeddingCfg(), targets, repo, locator)
}

// --- tests ---

func TestSemantic_Name(t *testing.T) {
	s := NewSemantic(nil, nil, nil, nil)
	assert.Equal(t, common.SemanticStrategyName, s.Name())
}

func TestSemantic_Next_NoTargets(t *testing.T) {
	s := NewSemantic(defaultEmbeddingCfg(), nil, nil, nil)
	result := s.Next(makeReqCtx(`{"prompt":"hello"}`))
	assert.Nil(t, result)
}

func TestSemantic_Next_SingleTarget(t *testing.T) {
	targets := makeTargets("billing")
	s := NewSemantic(defaultEmbeddingCfg(), targets, nil, nil)

	result := s.Next(makeReqCtx(`{"prompt":"hello"}`))
	require.NotNil(t, result)
	assert.Equal(t, "target-0", result.ID)
}

func TestSemantic_Next_NilEmbeddingConfig(t *testing.T) {
	targets := makeTargets("billing", "support")
	s := NewSemantic(nil, targets, nil, nil)

	result := s.Next(makeReqCtx(`{"prompt":"hello"}`))
	require.NotNil(t, result)
	assert.Equal(t, "target-0", result.ID)
}

func TestSemantic_Next_EmptyBody(t *testing.T) {
	targets := makeTargets("billing", "support")
	s := NewSemantic(defaultEmbeddingCfg(), targets, nil, nil)

	result := s.Next(makeReqCtx(""))
	require.NotNil(t, result)
	assert.Equal(t, "target-0", result.ID)
}

func TestSemantic_Next_InvalidJSON(t *testing.T) {
	targets := makeTargets("billing", "support")
	s := NewSemantic(defaultEmbeddingCfg(), targets, nil, nil)

	result := s.Next(makeReqCtx("{invalid json"))
	require.NotNil(t, result)
	assert.Equal(t, "target-0", result.ID)
}

func TestSemantic_Next_NoPromptField(t *testing.T) {
	targets := makeTargets("billing", "support")
	s := NewSemantic(defaultEmbeddingCfg(), targets, nil, nil)

	result := s.Next(makeReqCtx(`{"other_field": "value"}`))
	require.NotNil(t, result)
	assert.Equal(t, "target-0", result.ID)
}

func TestSemantic_Next_ServiceLocatorError(t *testing.T) {
	targets := makeTargets("billing", "support")
	locator := factoryMocks.NewEmbeddingServiceLocator(t)
	locator.EXPECT().GetService(mock.Anything).Return(nil, fmt.Errorf("locator error"))
	s := NewSemantic(defaultEmbeddingCfg(), targets, nil, locator)

	result := s.Next(makeReqCtx(`{"prompt":"pay my bill"}`))
	require.NotNil(t, result)
	assert.Equal(t, "target-0", result.ID)
}

func TestSemantic_Next_EmbeddingGenerationError(t *testing.T) {
	targets := makeTargets("billing", "support")
	creator := embeddingMocks.NewCreator(t)
	creator.EXPECT().Generate(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("openai error"))

	locator := factoryMocks.NewEmbeddingServiceLocator(t)
	locator.EXPECT().GetService(mock.Anything).Return(creator, nil)
	s := NewSemantic(defaultEmbeddingCfg(), targets, nil, locator)

	result := s.Next(makeReqCtx(`{"prompt":"pay my bill"}`))
	require.NotNil(t, result)
	assert.Equal(t, "target-0", result.ID)
}

func TestSemantic_Next_RoutesToBillingTarget(t *testing.T) {
	billingVec := normalize([]float64{1.0, 0.0, 0.0})
	supportVec := normalize([]float64{0.0, 1.0, 0.0})
	promptVec := normalize([]float64{0.9, 0.1, 0.0})

	targets := makeTargets("billing and payments", "technical support")
	s := setupSemanticWithRouting(t, targets, promptVec, map[string][]float64{
		"target-0": billingVec,
		"target-1": supportVec,
	})

	result := s.Next(makeReqCtx(`{"prompt":"pay my bill"}`))
	require.NotNil(t, result)
	assert.Equal(t, "target-0", result.ID)
}

func TestSemantic_Next_RoutesToSupportTarget(t *testing.T) {
	billingVec := normalize([]float64{1.0, 0.0, 0.0})
	supportVec := normalize([]float64{0.0, 1.0, 0.0})
	promptVec := normalize([]float64{0.1, 0.95, 0.0})

	targets := makeTargets("billing and payments", "technical support")
	s := setupSemanticWithRouting(t, targets, promptVec, map[string][]float64{
		"target-0": billingVec,
		"target-1": supportVec,
	})

	result := s.Next(makeReqCtx(`{"prompt":"my server is down"}`))
	require.NotNil(t, result)
	assert.Equal(t, "target-1", result.ID)
}

func TestSemantic_Next_MessagesFormat(t *testing.T) {
	billingVec := normalize([]float64{1.0, 0.0, 0.0})
	supportVec := normalize([]float64{0.0, 1.0, 0.0})
	promptVec := normalize([]float64{0.9, 0.1, 0.0})

	targets := makeTargets("billing and payments", "technical support")
	s := setupSemanticWithRouting(t, targets, promptVec, map[string][]float64{
		"target-0": billingVec,
		"target-1": supportVec,
	})

	body := `{"messages":[{"role":"user","content":"update my credit card"}]}`
	result := s.Next(makeReqCtx(body))
	require.NotNil(t, result)
	assert.Equal(t, "target-0", result.ID)
}

func TestSemantic_Next_MessagesUsesLastMessage(t *testing.T) {
	billingVec := normalize([]float64{1.0, 0.0, 0.0})
	supportVec := normalize([]float64{0.0, 1.0, 0.0})
	promptVec := normalize([]float64{0.1, 0.95, 0.0})

	targets := makeTargets("billing and payments", "technical support")
	s := setupSemanticWithRouting(t, targets, promptVec, map[string][]float64{
		"target-0": billingVec,
		"target-1": supportVec,
	})

	body := `{"messages":[{"role":"user","content":"pay my bill"},{"role":"assistant","content":"sure"},{"role":"user","content":"actually my server crashed"}]}`
	result := s.Next(makeReqCtx(body))
	require.NotNil(t, result)
	assert.Equal(t, "target-1", result.ID)
}

func TestSemantic_Next_SkipsTargetsWithoutDescription(t *testing.T) {
	supportVec := normalize([]float64{0.0, 1.0, 0.0})
	promptVec := normalize([]float64{0.1, 0.95, 0.0})

	targets := makeTargets("", "technical support")
	s := setupSemanticWithRouting(t, targets, promptVec, map[string][]float64{
		"target-1": supportVec,
	})

	result := s.Next(makeReqCtx(`{"prompt":"help me"}`))
	require.NotNil(t, result)
	assert.Equal(t, "target-1", result.ID)
}

func TestSemantic_Next_AllTargetsWithoutDescription(t *testing.T) {
	promptVec := normalize([]float64{0.5, 0.5, 0.0})

	targets := makeTargets("", "")
	repo := embeddingMocks.NewRepository(t)
	creator := embeddingMocks.NewCreator(t)
	creator.EXPECT().Generate(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&embedding.Embedding{Value: promptVec, CreatedAt: time.Now()}, nil)
	locator := factoryMocks.NewEmbeddingServiceLocator(t)
	locator.EXPECT().GetService(mock.Anything).Return(creator, nil)
	s := NewSemantic(defaultEmbeddingCfg(), targets, repo, locator)

	result := s.Next(makeReqCtx(`{"prompt":"hello"}`))
	require.NotNil(t, result)
	assert.Equal(t, "target-0", result.ID)
}

func TestSemantic_Next_EmbeddingRepoError(t *testing.T) {
	promptVec := normalize([]float64{0.5, 0.5, 0.0})

	targets := makeTargets("billing", "support")
	repo := embeddingMocks.NewRepository(t)
	repo.EXPECT().GetByTargetID(mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("redis down"))

	creator := embeddingMocks.NewCreator(t)
	creator.EXPECT().Generate(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&embedding.Embedding{Value: promptVec, CreatedAt: time.Now()}, nil)
	locator := factoryMocks.NewEmbeddingServiceLocator(t)
	locator.EXPECT().GetService(mock.Anything).Return(creator, nil)
	s := NewSemantic(defaultEmbeddingCfg(), targets, repo, locator)

	result := s.Next(makeReqCtx(`{"prompt":"hello"}`))
	require.NotNil(t, result)
	assert.Equal(t, "target-0", result.ID)
}

func TestSemantic_Next_ThreeTargets(t *testing.T) {
	billingVec := normalize([]float64{1.0, 0.0, 0.0})
	supportVec := normalize([]float64{0.0, 1.0, 0.0})
	salesVec := normalize([]float64{0.0, 0.0, 1.0})
	promptVec := normalize([]float64{0.0, 0.0, 0.9})

	targets := makeTargets("billing", "support", "sales")
	s := setupSemanticWithRouting(t, targets, promptVec, map[string][]float64{
		"target-0": billingVec,
		"target-1": supportVec,
		"target-2": salesVec,
	})

	result := s.Next(makeReqCtx(`{"prompt":"I want to buy"}`))
	require.NotNil(t, result)
	assert.Equal(t, "target-2", result.ID)
}

// --- buildEmbeddingConfig credential tests ---

func TestBuildEmbeddingConfig_ApiKey(t *testing.T) {
	cfg := &types.EmbeddingConfigDTO{
		Provider: "openai",
		Model:    "text-embedding-3-small",
		Credentials: types.CredentialsDTO{
			ApiKey: "sk-test-key",
		},
	}
	s := NewSemantic(cfg, nil, nil, nil)
	require.NotNil(t, s.embeddingConfig)
	assert.Equal(t, "sk-test-key", s.embeddingConfig.Credentials.ApiKey)
	assert.Equal(t, "openai", s.embeddingConfig.Provider)
	assert.Equal(t, "text-embedding-3-small", s.embeddingConfig.Model)
}

func TestBuildEmbeddingConfig_HeaderValueFallback(t *testing.T) {
	cfg := &types.EmbeddingConfigDTO{
		Provider: "openai",
		Model:    "text-embedding-3-small",
		Credentials: types.CredentialsDTO{
			HeaderName:  "Authorization",
			HeaderValue: "sk-from-header",
		},
	}
	s := NewSemantic(cfg, nil, nil, nil)
	require.NotNil(t, s.embeddingConfig)
	assert.Equal(t, "sk-from-header", s.embeddingConfig.Credentials.ApiKey)
	assert.Equal(t, "Authorization", s.embeddingConfig.Credentials.HeaderName)
	assert.Equal(t, "sk-from-header", s.embeddingConfig.Credentials.HeaderValue)
}

func TestBuildEmbeddingConfig_ApiKeyTakesPrecedence(t *testing.T) {
	cfg := &types.EmbeddingConfigDTO{
		Provider: "openai",
		Model:    "text-embedding-3-small",
		Credentials: types.CredentialsDTO{
			ApiKey:      "sk-api-key",
			HeaderName:  "Authorization",
			HeaderValue: "sk-header-value",
		},
	}
	s := NewSemantic(cfg, nil, nil, nil)
	require.NotNil(t, s.embeddingConfig)
	assert.Equal(t, "sk-api-key", s.embeddingConfig.Credentials.ApiKey)
}

func TestBuildEmbeddingConfig_NoCredentials(t *testing.T) {
	cfg := &types.EmbeddingConfigDTO{
		Provider:    "openai",
		Model:       "text-embedding-3-small",
		Credentials: types.CredentialsDTO{},
	}
	s := NewSemantic(cfg, nil, nil, nil)
	require.NotNil(t, s.embeddingConfig)
	assert.Empty(t, s.embeddingConfig.Credentials.ApiKey)
}

// --- extractPromptFromRequest tests ---

func TestExtractPrompt_PromptField(t *testing.T) {
	s := &Semantic{}
	prompt, err := s.extractPromptFromRequest([]byte(`{"prompt":"hello world"}`))
	require.NoError(t, err)
	assert.Equal(t, "hello world", prompt)
}

func TestExtractPrompt_MessagesField(t *testing.T) {
	s := &Semantic{}
	body := `{"messages":[{"role":"system","content":"you are helpful"},{"role":"user","content":"what is AI?"}]}`
	prompt, err := s.extractPromptFromRequest([]byte(body))
	require.NoError(t, err)
	assert.Equal(t, "what is AI?", prompt)
}

func TestExtractPrompt_PromptTakesPrecedence(t *testing.T) {
	s := &Semantic{}
	body := `{"prompt":"direct prompt","messages":[{"role":"user","content":"from messages"}]}`
	prompt, err := s.extractPromptFromRequest([]byte(body))
	require.NoError(t, err)
	assert.Equal(t, "direct prompt", prompt)
}

func TestExtractPrompt_EmptyBody(t *testing.T) {
	s := &Semantic{}
	_, err := s.extractPromptFromRequest(nil)
	assert.Error(t, err)
}

func TestExtractPrompt_InvalidJSON(t *testing.T) {
	s := &Semantic{}
	_, err := s.extractPromptFromRequest([]byte("{bad json"))
	assert.Error(t, err)
}

func TestExtractPrompt_EmptyMessages(t *testing.T) {
	s := &Semantic{}
	_, err := s.extractPromptFromRequest([]byte(`{"messages":[]}`))
	assert.Error(t, err)
}

func TestExtractPrompt_MessageWithoutContent(t *testing.T) {
	s := &Semantic{}
	_, err := s.extractPromptFromRequest([]byte(`{"messages":[{"role":"user"}]}`))
	assert.Error(t, err)
}

// --- cosineSimilarity tests ---

func TestCosineSimilarity_IdenticalVectors(t *testing.T) {
	v := []float64{1.0, 2.0, 3.0}
	sim := cosineSimilarity(v, v)
	assert.InDelta(t, 1.0, sim, 1e-10)
}

func TestCosineSimilarity_OrthogonalVectors(t *testing.T) {
	a := []float64{1.0, 0.0, 0.0}
	b := []float64{0.0, 1.0, 0.0}
	sim := cosineSimilarity(a, b)
	assert.InDelta(t, 0.0, sim, 1e-10)
}

func TestCosineSimilarity_OppositeVectors(t *testing.T) {
	a := []float64{1.0, 0.0}
	b := []float64{-1.0, 0.0}
	sim := cosineSimilarity(a, b)
	assert.InDelta(t, -1.0, sim, 1e-10)
}

func TestCosineSimilarity_DifferentLengths(t *testing.T) {
	a := []float64{1.0, 2.0}
	b := []float64{1.0, 2.0, 3.0}
	sim := cosineSimilarity(a, b)
	assert.Equal(t, 0.0, sim)
}

func TestCosineSimilarity_ZeroVector(t *testing.T) {
	a := []float64{0.0, 0.0, 0.0}
	b := []float64{1.0, 2.0, 3.0}
	sim := cosineSimilarity(a, b)
	assert.Equal(t, 0.0, sim)
}

func TestCosineSimilarity_NormalizedVectors(t *testing.T) {
	a := normalize([]float64{3.0, 4.0})
	b := normalize([]float64{4.0, 3.0})
	sim := cosineSimilarity(a, b)
	expected := 24.0 / 25.0
	assert.InDelta(t, expected, sim, 1e-10)
}
