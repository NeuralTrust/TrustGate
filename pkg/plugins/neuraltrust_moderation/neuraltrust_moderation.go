package neuraltrust_moderation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	providersFactory "github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

const (
	PluginName = "neuraltrust_moderation"
	cacheKey   = "plugin:%s:neuraltrust_moderation:deny_sample:%s"
)

type LLMResponse struct {
	Topic            string `json:"topic"`
	InstructionMatch string `json:"instruction_match"`
	Flagged          bool   `json:"flagged"`
}

type NeuralTrustModerationPlugin struct {
	client             httpx.Client
	fingerPrintManager fingerprint.Tracker
	logger             *logrus.Logger
	embeddingRepo      embedding.EmbeddingRepository
	serviceLocator     factory.EmbeddingServiceLocator
	config             Config
	providerLocator    providersFactory.ProviderLocator
	bufferPool         sync.Pool
	byteSlicePool      sync.Pool
	keywords           []string
	regexRules         []*regexp.Regexp
}

func NewNeuralTrustModerationPlugin(
	logger *logrus.Logger,
	client httpx.Client,
	fingerPrintManager fingerprint.Tracker,
	embeddingRepo embedding.EmbeddingRepository,
	serviceLocator factory.EmbeddingServiceLocator,
	providerLocator providersFactory.ProviderLocator,
) pluginiface.Plugin {
	if client == nil {
		client = &http.Client{}
	}
	return &NeuralTrustModerationPlugin{
		client:             client,
		logger:             logger,
		fingerPrintManager: fingerPrintManager,
		embeddingRepo:      embeddingRepo,
		serviceLocator:     serviceLocator,
		keywords:           make([]string, 0),
		regexRules:         make([]*regexp.Regexp, 0),
		providerLocator:    providerLocator,
		bufferPool: sync.Pool{
			New: func() any {
				return new(bytes.Buffer)
			},
		},
		byteSlicePool: sync.Pool{
			New: func() any {
				return make([]byte, 4096)
			},
		},
	}
}

func (p *NeuralTrustModerationPlugin) Name() string {
	return PluginName
}

func (p *NeuralTrustModerationPlugin) RequiredPlugins() []string {
	var requiredPlugins []string
	return requiredPlugins
}

func (p *NeuralTrustModerationPlugin) Stages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *NeuralTrustModerationPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *NeuralTrustModerationPlugin) ValidateConfig(config types.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}

	if cfg.EmbeddingParamBag != nil && cfg.EmbeddingParamBag.Enabled {
		if cfg.EmbeddingParamBag.EmbeddingsConfig.Provider != providersFactory.ProviderOpenAI {
			return fmt.Errorf("embedding provider must be '%s'", providersFactory.ProviderOpenAI)
		}
		if cfg.EmbeddingParamBag.Threshold == 0 {
			return fmt.Errorf("moderation threshold is required")
		}
		if cfg.EmbeddingParamBag.Threshold > 1 {
			return fmt.Errorf("moderation threshold must be between 0 and 1")
		}
		if cfg.EmbeddingParamBag.DenyTopicAction != "block" {
			return fmt.Errorf("deny topic action must be block")
		}
		err := p.validateEmbeddingCredentials(cfg.EmbeddingParamBag.EmbeddingsConfig.Credentials)
		if err != nil {
			return err
		}
	}

	if cfg.KeyRegParamBag != nil && cfg.KeyRegParamBag.Enabled {
		if len(cfg.KeyRegParamBag.Keywords) == 0 && len(cfg.KeyRegParamBag.Regex) == 0 {
			return fmt.Errorf("at least one keyword or regex pattern must be specified")
		}
		for _, pattern := range cfg.KeyRegParamBag.Regex {
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("invalid regex pattern '%s': %v", pattern, err)
			}
		}
		if cfg.KeyRegParamBag.Actions.Type == "" {
			return fmt.Errorf("action type must be specified")
		}
	}

	if cfg.LLMParamBag != nil {
		if cfg.LLMParamBag.Provider != providersFactory.ProviderOpenAI &&
			cfg.LLMParamBag.Provider != providersFactory.ProviderAnthropic &&
			cfg.LLMParamBag.Provider != providersFactory.ProviderGemini {
			return fmt.Errorf("LLM provider must be either '%s' or '%s' or '%s'",
				providersFactory.ProviderOpenAI,
				providersFactory.ProviderGemini,
				providersFactory.ProviderAnthropic,
			)
		}
		if cfg.LLMParamBag.Model == "" {
			return fmt.Errorf("LLM model cannot be empty")
		}
		err := p.validateCredentials(cfg.LLMParamBag.Credentials)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *NeuralTrustModerationPlugin) validateCredentials(credentials Credentials) error {
	if credentials.ApiKey == "" {
		return fmt.Errorf("apikey must be specified")
	}
	return nil
}

func (p *NeuralTrustModerationPlugin) validateEmbeddingCredentials(credentials EmbeddingCredentials) error {
	if credentials.HeaderValue == "" || credentials.HeaderName == "" {
		return fmt.Errorf("credentials must be specified")
	}
	return nil
}

func (p *NeuralTrustModerationPlugin) Execute(
	ctx context.Context,
	cfg types.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	evtCtx *metrics.EventContext,
) (*types.PluginResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var conf Config
	if err := mapstructure.Decode(cfg.Settings, &conf); err != nil {
		p.logger.WithError(err).Error("failed to decode config")
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}
	p.config = conf

	inputBody := req.Body
	inputBody, err := p.defineRequestBody(inputBody)
	if err != nil {
		p.logger.WithError(err).Error("failed to define request body")
		return nil, fmt.Errorf("failed to define request body: %w", err)
	}

	if req.Stage == types.PostRequest {
		inputBody = resp.Body
	}

	evt := &NeuralTrustModerationData{
		EmbeddingModeration: &EmbeddingModeration{
			Scores: &EmbeddingScores{
				Scores: make(map[string]float64),
			},
		},
		KeyRegModeration: &KeyRegModeration{
			Reason: KeyRegReason{},
		},
	}

	firewallErrors := make(chan error, 1)
	var wg sync.WaitGroup

	keyRegFound := false
	if p.config.KeyRegParamBag != nil && p.config.KeyRegParamBag.Enabled {
		p.keywords = p.config.KeyRegParamBag.Keywords
		p.regexRules = make([]*regexp.Regexp, len(p.config.KeyRegParamBag.Regex))
		for i, pattern := range p.config.KeyRegParamBag.Regex {
			regex, err := regexp.Compile(pattern)
			if err != nil {
				p.logger.WithError(err).Error("failed to compile regex pattern")
				return nil, fmt.Errorf("failed to compile regex pattern '%s': %v", pattern, err)
			}
			p.regexRules[i] = regex
		}
		keyRegFound = p.callKeyRegModeration(ctx, p.config.KeyRegParamBag, inputBody, firewallErrors, evt)
	}

	if !keyRegFound && p.config.EmbeddingParamBag != nil && p.config.EmbeddingParamBag.Enabled {
		evt.EmbeddingModeration.Threshold = p.config.EmbeddingParamBag.Threshold
		if len(p.config.EmbeddingParamBag.DenySamples) > 0 {
			err := p.createEmbeddings(ctx, p.config.EmbeddingParamBag, req.GatewayID)
			if err != nil {
				p.logger.WithError(err).Error("failed to create deny samples embeddings")
				return nil, fmt.Errorf("failed to create deny samples embeddings: %w", err)
			}
		}

		wg.Add(1)
		go p.callEmbeddingModeration(ctx, p.config.EmbeddingParamBag, &wg, inputBody, req.GatewayID, firewallErrors, evt)
	}

	if !keyRegFound && p.config.LLMParamBag != nil && p.config.LLMParamBag.Enabled {
		wg.Add(1)
		go p.callAIModeration(
			ctx,
			p.config.LLMParamBag,
			&wg,
			inputBody,
			firewallErrors,
			evt,
		)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
		close(firewallErrors)
	}()

	select {
	case err, ok := <-firewallErrors:
		if !ok {
			break
		}
		if err != nil {
			p.notifyGuardrailViolation(ctx)
			cancel()
			var moderationViolationError *moderationViolationError
			if errors.As(err, &moderationViolationError) {
				evtCtx.SetError(moderationViolationError)
				evtCtx.SetExtras(evt)
				return nil, &types.PluginError{
					StatusCode: http.StatusForbidden,
					Message:    err.Error(),
					Err:        err,
				}
			}
			evtCtx.SetError(err)
			evtCtx.SetExtras(evt)
			return nil, &types.PluginError{
				StatusCode: http.StatusInternalServerError,
				Message:    "internal server error",
				Err:        err,
			}
		}
	case <-done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	evtCtx.SetExtras(evt)

	return &types.PluginResponse{
		StatusCode: 200,
		Message:    "prompt content is safe",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body: nil,
	}, nil
}

func (p *NeuralTrustModerationPlugin) createEmbeddings(
	ctx context.Context,
	cfg *EmbeddingParamBag,
	gatewayID string,
) error {
	if !cfg.Enabled {
		return nil
	}
	if len(cfg.DenySamples) == 0 {
		return nil
	}

	total, err := p.embeddingRepo.Count(ctx, common.NeuralTrustGuardRailIndexName, gatewayID)
	if err != nil {
		return fmt.Errorf("failed to count embeddings: %w", err)
	}
	if total >= len(cfg.DenySamples) {
		return nil
	}

	creator, err := p.serviceLocator.GetService(cfg.EmbeddingsConfig.Provider)
	if err != nil {
		return fmt.Errorf("failed to create embeddings: %w", err)
	}
	config := &embedding.Config{
		Provider: cfg.EmbeddingsConfig.Provider,
		Model:    cfg.EmbeddingsConfig.Model,
		Credentials: domain.CredentialsJSON{
			HeaderValue: cfg.EmbeddingsConfig.Credentials.HeaderValue,
			HeaderName:  cfg.EmbeddingsConfig.Credentials.HeaderName,
		},
	}
	wg := &sync.WaitGroup{}
	wg.Add(len(cfg.DenySamples))
	for _, sample := range cfg.DenySamples {
		go p.generateSampleEmbedding(
			wg,
			ctx,
			cfg.EmbeddingsConfig.Model,
			sample,
			gatewayID,
			creator,
			config,
		)
	}
	wg.Wait()
	return nil
}

func (p *NeuralTrustModerationPlugin) generateSampleEmbedding(
	wg *sync.WaitGroup,
	ctx context.Context,
	model, sample, gatewayID string,
	creator embedding.Creator,
	config *embedding.Config,
) {
	defer wg.Done()
	embeddingData, err := creator.Generate(ctx, sample, model, config)
	if err != nil {
		p.logger.WithError(err).Error("failed to generate embedding for sample " + sample)
	}

	err = p.embeddingRepo.StoreWithHMSet(
		ctx,
		common.NeuralTrustGuardRailIndexName,
		fmt.Sprintf(cacheKey, gatewayID, uuid.New().String()),
		gatewayID,
		embeddingData,
		[]byte(sample),
	)
	if err != nil {
		p.logger.WithError(err).Error("failed to store embedding for sample " + sample)
	}
}

func (p *NeuralTrustModerationPlugin) hashGatewayID(value string) string {
	h := sha256.New()
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}

func (p *NeuralTrustModerationPlugin) notifyGuardrailViolation(ctx context.Context) {
	fp, ok := ctx.Value(common.FingerprintIdContextKey).(string)
	if !ok {
		return
	}
	storedFp, err := p.fingerPrintManager.GetFingerprint(ctx, fp)
	if err != nil {
		p.logger.WithError(err).Error("failed to get fingerprint (neuraltrust_moderation)")
		return
	}
	if storedFp != nil {
		ttl := fingerprint.DefaultExpiration
		if p.config.RetentionPeriod == 0 {
			p.config.RetentionPeriod = 60
			ttl = time.Duration(p.config.RetentionPeriod) * time.Second
		}
		err = p.fingerPrintManager.IncrementMaliciousCount(ctx, fp, ttl)
		if err != nil {
			p.logger.WithError(err).Error("failed to increment malicious count")
			return
		}
	}
}

func (p *NeuralTrustModerationPlugin) callAIModeration(
	ctx context.Context,
	cfg *LLMModParamBag,
	wg *sync.WaitGroup,
	inputBody []byte,
	firewallErrors chan<- error,
	evt *NeuralTrustModerationData,
) {
	defer wg.Done()

	client, err := p.providerLocator.Get(cfg.Provider)
	if err != nil {
		p.logger.WithError(err).Error("failed to get llm provider")
		p.sendError(firewallErrors, err)
		return
	}

	maxTokens := cfg.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 1000
	}
	start := time.Now()
	response, err := client.Ask(ctx, &providers.Config{
		Credentials: providers.Credentials{
			ApiKey: cfg.Credentials.ApiKey,
		},
		Model:        cfg.Model,
		MaxTokens:    maxTokens,
		Temperature:  0.5,
		SystemPrompt: SystemPrompt,
		Instructions: cfg.Instructions,
	}, string(inputBody))
	duration := time.Since(start).Seconds()
	if err != nil {
		p.logger.WithError(err).Error("failed to call llm provider")
		p.sendError(firewallErrors, err)
		return
	}
	p.logger.WithField("duration", duration).Info("LLM provider responded successfully")

	if response == nil {
		err := errors.New("llm provider returned nil response")
		p.logger.WithError(err).Error("nil response from provider")
		p.sendError(firewallErrors, err)
		return
	}

	var resp LLMResponse
	if err := json.Unmarshal([]byte(response.Response), &resp); err != nil {
		p.logger.WithError(err).Error("failed to unmarshal llm response")
		p.sendError(firewallErrors, err)
		return
	}

	evt.LLMModeration = &LLMModeration{
		Blocked:          resp.Flagged,
		InstructionMatch: resp.InstructionMatch,
		Model:            cfg.Model,
		Provider:         cfg.Provider,
		Topic:            resp.Topic,
	}

	if resp.Flagged {
		p.sendError(firewallErrors, NewModerationViolation("content blocked"))
	}
}

func (p *NeuralTrustModerationPlugin) callEmbeddingModeration(
	ctx context.Context,
	cfg *EmbeddingParamBag,
	wg *sync.WaitGroup,
	inputBody []byte,
	gatewayID string,
	firewallErrors chan<- error,
	evt *NeuralTrustModerationData,
) {
	defer wg.Done()
	if len(inputBody) == 0 {
		return
	}
	creator, err := p.serviceLocator.GetService(cfg.EmbeddingsConfig.Provider)
	if err != nil {
		p.logger.WithError(err).Error("failed to get embeddings service")
		p.sendError(firewallErrors, err)
		return
	}
	config := &embedding.Config{
		Provider: cfg.EmbeddingsConfig.Provider,
		Model:    cfg.EmbeddingsConfig.Model,
		Credentials: domain.CredentialsJSON{
			HeaderValue: cfg.EmbeddingsConfig.Credentials.HeaderValue,
			HeaderName:  cfg.EmbeddingsConfig.Credentials.HeaderName,
		},
	}
	emb, err := creator.Generate(ctx, string(inputBody), cfg.EmbeddingsConfig.Model, config)
	if err != nil {
		p.logger.WithError(err).Error("failed to generate body embedding")
		p.sendError(firewallErrors, err)
		return
	}

	query := fmt.Sprintf("@gateway_id:{%s}=>[KNN 5 @embedding $BLOB AS score]", p.hashGatewayID(gatewayID))

	results, err := p.embeddingRepo.Search(ctx, common.NeuralTrustGuardRailIndexName, query, emb)
	if err != nil {
		p.logger.WithError(err).Error("failed to search embeddings")
		p.sendError(firewallErrors, err)
		return
	}
	if len(results) == 0 {
		return
	}

	scores := make(map[string]float64, len(results))
	for _, result := range results {
		scores[result.Data] = result.Score
	}

	evt.EmbeddingModeration.Scores.Scores = scores
	evt.EmbeddingModeration.Threshold = cfg.Threshold

	for _, result := range results {
		if result.Score >= cfg.Threshold {
			p.sendError(
				firewallErrors,
				NewModerationViolation(fmt.Sprintf("content blocked: with similarity score %f exceeds threshold %f",
					result.Score,
					cfg.Threshold,
				),
				),
			)
			return
		}
	}
}

func (p *NeuralTrustModerationPlugin) sendError(ch chan<- error, err error) {
	select {
	case ch <- err:
	default:
	}
}

func (p *NeuralTrustModerationPlugin) callKeyRegModeration(
	ctx context.Context,
	cfg *KeyRegParamBag,
	inputBody []byte,
	firewallErrors chan<- error,
	evt *NeuralTrustModerationData,
) bool {
	if len(inputBody) == 0 {
		return false
	}

	content := string(inputBody)
	threshold := cfg.SimilarityThreshold
	if threshold == 0 {
		threshold = 0.8
	}

	if foundWord, keyword, found := p.findSimilarKeyword(content, threshold); found {
		evt.KeyRegModeration.SimilarityThreshold = threshold
		evt.KeyRegModeration.Reason = KeyRegReason{
			Type:    "keyword",
			Pattern: keyword,
			Match:   foundWord,
		}
		p.sendError(
			firewallErrors,
			NewModerationViolation(
				fmt.Sprintf("content blocked: word '%s' is similar to blocked keyword '%s'",
					foundWord,
					keyword,
				),
			),
		)
		return true
	}

	for _, pattern := range p.regexRules {
		matches := pattern.FindStringSubmatch(content)
		if len(matches) > 0 {
			evt.KeyRegModeration.SimilarityThreshold = threshold
			evt.KeyRegModeration.Reason = KeyRegReason{
				Type:    "regex",
				Pattern: pattern.String(),
				Match:   matches[0],
			}
			p.sendError(
				firewallErrors,
				NewModerationViolation(fmt.Sprintf("content blocked: regex pattern %s found in request body", pattern)),
			)
			return true
		}
	}
	return false
}

func (p *NeuralTrustModerationPlugin) defineRequestBody(body []byte) ([]byte, error) {
	buf, ok := p.bufferPool.Get().(*bytes.Buffer)
	if !ok {
		return nil, fmt.Errorf("failed to get buffer from pool")
	}
	buf.Reset()
	defer p.bufferPool.Put(buf)

	var requestBody map[string]interface{}
	if err := json.Unmarshal(body, &requestBody); err != nil {
		return p.returnDefaultBody(body)
	}

	if p.config.MappingField == "" {
		return p.returnDefaultBody(body)
	}

	path := strings.Split(p.config.MappingField, ".")
	current := any(requestBody)

	for _, key := range path {
		m, ok := current.(map[string]interface{})
		if !ok {
			return p.returnDefaultBody(body)
		}
		child, exists := m[key]
		if !exists {
			return p.returnDefaultBody(body)
		}
		current = child
	}

	var inputString string
	switch v := current.(type) {
	case string:
		inputString = v
	default:
		if err := json.NewEncoder(buf).Encode(v); err != nil {
			return nil, fmt.Errorf("failed to stringify extracted value: %w", err)
		}
		inputString = buf.String()
	}

	result, err := json.Marshal(map[string]interface{}{
		"input": inputString,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal wrapped input: %w", err)
	}

	return result, nil
}

func (p *NeuralTrustModerationPlugin) returnDefaultBody(body []byte) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"input": string(body),
	})
}

func (p *NeuralTrustModerationPlugin) levenshteinDistance(s1, s2 string) int {
	s1 = strings.ToLower(s1)
	s2 = strings.ToLower(s2)

	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 1
			if s1[i-1] == s2[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,
				matrix[i][j-1]+1,
				matrix[i-1][j-1]+cost,
			)
		}
	}
	return matrix[len(s1)][len(s2)]
}

func (p *NeuralTrustModerationPlugin) calculateSimilarity(s1, s2 string) float64 {
	distance := p.levenshteinDistance(s1, s2)
	maxLen := float64(max(len(s1), len(s2)))
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - float64(distance)/maxLen
}

func (p *NeuralTrustModerationPlugin) findSimilarKeyword(text string, threshold float64) (string, string, bool) {
	words := strings.Fields(text)
	for _, word := range words {
		for _, keyword := range p.keywords {
			similarity := p.calculateSimilarity(word, keyword)
			if similarity >= threshold {
				return word, keyword, true
			}
		}
	}
	return "", "", false
}
