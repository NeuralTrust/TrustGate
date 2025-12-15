package neuraltrust_moderation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
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
	"github.com/NeuralTrust/TrustGate/pkg/pluginutils"
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
	providerLocator    providersFactory.ProviderLocator
	bufferPool         sync.Pool
	byteSlicePool      sync.Pool
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
		client = &http.Client{ //nolint
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402
			},
		}
	}
	return &NeuralTrustModerationPlugin{
		client:             client,
		logger:             logger,
		fingerPrintManager: fingerPrintManager,
		embeddingRepo:      embeddingRepo,
		serviceLocator:     serviceLocator,
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
			cfg.LLMParamBag.Provider != providersFactory.ProviderAzure &&
			cfg.LLMParamBag.Provider != providersFactory.ProviderGoogle {
			return fmt.Errorf("LLM provider must be either '%s' or '%s' or '%s' or '%s'",
				providersFactory.ProviderOpenAI,
				providersFactory.ProviderGoogle,
				providersFactory.ProviderAnthropic,
				providersFactory.ProviderAzure,
			)
		}
		if cfg.LLMParamBag.Model == "" {
			return fmt.Errorf("LLM model cannot be empty")
		}
		err := p.validateCredentials(cfg.LLMParamBag.Provider, cfg.LLMParamBag.Credentials)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *NeuralTrustModerationPlugin) validateCredentials(provider string, credentials Credentials) error {
	if credentials.ApiKey == "" {
		return fmt.Errorf("apikey must be specified")
	}
	if provider == providersFactory.ProviderAzure && (credentials.Azure == nil || credentials.Azure.Endpoint == "") {
		return fmt.Errorf("azure endpoint must be specified")
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

	firewallErrors := make(chan error, 1)
	var wg sync.WaitGroup
	var evtMu sync.Mutex
	var keywords []string
	var regexRules []*regexp.Regexp

	inputBody := req.Body

	if req.Stage == types.PostRequest {
		inputBody = resp.Body
	}

	mappingContent, err := pluginutils.DefineRequestBody(inputBody, conf.MappingField)
	if err != nil {
		p.logger.WithError(err).Error("failed to define request body")
		return nil, fmt.Errorf("failed to define request body: %w", err)
	}

	// Convert to []byte once and reuse
	inputBytes := []byte(mappingContent.Input)

	evt := &NeuralTrustModerationData{
		MappingField: conf.MappingField,
		InputLength:  len(mappingContent.Input),
		Blocked:      false,
	}

	keyRegFound := false
	if conf.KeyRegParamBag != nil && conf.KeyRegParamBag.Enabled {
		keywords = conf.KeyRegParamBag.Keywords
		regexRules = make([]*regexp.Regexp, len(conf.KeyRegParamBag.Regex))
		for i, pattern := range conf.KeyRegParamBag.Regex {
			regex, err := regexp.Compile(pattern)
			if err != nil {
				p.logger.WithError(err).Error("failed to compile regex pattern")
				return nil, fmt.Errorf("failed to compile regex pattern '%s': %v", pattern, err)
			}
			regexRules[i] = regex
		}

		evt.KeyRegModeration = &KeyRegModeration{
			SimilarityThreshold: conf.KeyRegParamBag.SimilarityThreshold,
		}
		if evt.KeyRegModeration.SimilarityThreshold == 0 {
			evt.KeyRegModeration.SimilarityThreshold = 0.8
		}

		keyRegFound = p.callKeyRegModeration(
			ctx,
			conf.KeyRegParamBag,
			inputBytes,
			firewallErrors,
			evt,
			keywords,
			regexRules,
		)

		if keyRegFound {
			evt.Blocked = true
			evt.KeyRegModeration.Blocked = true
		}
	}

	if !keyRegFound && conf.EmbeddingParamBag != nil && conf.EmbeddingParamBag.Enabled {
		evt.EmbeddingModeration = &EmbeddingModeration{
			Provider:  conf.EmbeddingParamBag.EmbeddingsConfig.Provider,
			Model:     conf.EmbeddingParamBag.EmbeddingsConfig.Model,
			Threshold: conf.EmbeddingParamBag.Threshold,
			Scores: &EmbeddingScores{
				Scores: make(map[string]float64),
			},
		}

		if len(conf.EmbeddingParamBag.DenySamples) > 0 {
			err := p.createEmbeddings(ctx, conf.EmbeddingParamBag, req.GatewayID)
			if err != nil {
				p.logger.WithError(err).Error("failed to create deny samples embeddings")
				return nil, fmt.Errorf("failed to create deny samples embeddings: %w", err)
			}
		}

		wg.Add(1)
		go p.callEmbeddingModeration(
			ctx,
			conf.EmbeddingParamBag,
			&wg,
			inputBytes,
			req.GatewayID,
			firewallErrors,
			evt,
			&evtMu,
		)
	}

	if !keyRegFound && conf.LLMParamBag != nil && conf.LLMParamBag.Enabled {
		evt.LLMModeration = &LLMModeration{}

		wg.Add(1)
		go p.callAIModeration(
			ctx,
			conf.LLMParamBag,
			&wg,
			inputBytes,
			firewallErrors,
			evt,
			&evtMu,
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
			evt.Blocked = true
			p.notifyGuardrailViolation(ctx, conf)
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
			return nil, err
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

	total, err := p.embeddingRepo.Count(ctx, common.NeuralTrustJailbreakIndexName, gatewayID)
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
		return
	}

	if embeddingData == nil {
		p.logger.Error("embedding data is nil for sample " + sample)
		return
	}

	err = p.embeddingRepo.StoreWithHMSet(
		ctx,
		common.NeuralTrustJailbreakIndexName,
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

func (p *NeuralTrustModerationPlugin) notifyGuardrailViolation(ctx context.Context, conf Config) {
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
		if conf.RetentionPeriod == 0 {
			conf.RetentionPeriod = 60
			ttl = time.Duration(conf.RetentionPeriod) * time.Second
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
	evtMu *sync.Mutex,
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

	providersCreds := providers.Credentials{
		ApiKey: cfg.Credentials.ApiKey,
	}

	if cfg.Credentials.Azure != nil {
		providersCreds.Azure = &providers.Azure{
			Endpoint:    cfg.Credentials.Azure.Endpoint,
			UseIdentity: cfg.Credentials.Azure.UseManagedIdentity,
			ApiVersion:  cfg.Credentials.Azure.ApiVersion,
		}
	}

	response, err := client.Ask(ctx, &providers.Config{
		Credentials:  providersCreds,
		Model:        cfg.Model,
		MaxTokens:    maxTokens,
		Temperature:  0.0,
		SystemPrompt: SystemPrompt,
		Instructions: cfg.Instructions,
	}, string(inputBody))
	duration := time.Since(start).Seconds()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		p.logger.WithError(err).Error("failed to call llm provider")
		p.sendError(firewallErrors, err)
		return
	}

	if response == nil {
		err := errors.New("LLM provider returned nil response")
		p.logger.WithError(err).Error("nil response from LLM provider")
		p.sendError(firewallErrors, err)
		return
	} else {
		p.logger.WithFields(logrus.Fields{"duration": duration, "response_body": response.Response}).
			Info("LLM provider responded successfully")
	}

	var resp LLMResponse
	if err := json.Unmarshal([]byte(response.Response), &resp); err != nil {
		p.logger.WithError(err).Error("failed to unmarshal llm response")
		p.sendError(firewallErrors, err)
		return
	}

	if evtMu != nil {
		evtMu.Lock()
	}
	if evt.LLMModeration != nil {
		evt.LLMModeration.Blocked = resp.Flagged
		evt.LLMModeration.InstructionMatch = resp.InstructionMatch
		evt.LLMModeration.Topic = resp.Topic
		evt.LLMModeration.DetectionLatencyMs = int64(duration * 1000)
	}
	if evtMu != nil {
		evtMu.Unlock()
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
	evtMu *sync.Mutex,
) {
	defer wg.Done()
	if len(inputBody) == 0 {
		return
	}

	startTime := time.Now()

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
		if errors.Is(err, embedding.ErrProviderNonOKResponse) {
			p.logger.WithError(err).Warn("embedding provider non-ok response; skipping moderation signal")
			return
		}
		p.logger.WithError(err).Error("failed to generate body embedding")
		p.sendError(firewallErrors, err)
		return
	}

	query := fmt.Sprintf("@gateway_id:{%s}=>[KNN 5 @embedding $BLOB AS score]", p.hashGatewayID(gatewayID))

	results, err := p.embeddingRepo.Search(ctx, common.NeuralTrustJailbreakIndexName, query, emb)

	latencyMs := time.Since(startTime).Milliseconds()

	if err != nil {
		p.logger.WithError(err).Error("failed to search embeddings")
		p.sendError(firewallErrors, err)
		return
	}

	if evtMu != nil {
		evtMu.Lock()
	}
	if evt.EmbeddingModeration != nil {
		evt.EmbeddingModeration.DetectionLatencyMs = latencyMs
	}
	if evtMu != nil {
		evtMu.Unlock()
	}

	if len(results) == 0 {
		return
	}

	scores := make(map[string]float64, len(results))
	var maxScore float64
	matchCount := 0
	blocked := false

	for _, result := range results {
		scores[result.Data] = result.Score
		if result.Score > maxScore {
			maxScore = result.Score
		}
		if result.Score >= cfg.Threshold {
			matchCount++
			blocked = true
		}
	}

	if evtMu != nil {
		evtMu.Lock()
	}
	if evt.EmbeddingModeration != nil && evt.EmbeddingModeration.Scores != nil {
		evt.EmbeddingModeration.Scores.Scores = scores
		evt.EmbeddingModeration.Scores.MaxScore = maxScore
		evt.EmbeddingModeration.Scores.MatchCount = matchCount
		evt.EmbeddingModeration.Blocked = blocked
	}
	if evtMu != nil {
		evtMu.Unlock()
	}

	if blocked {
		p.sendError(
			firewallErrors,
			NewModerationViolation(fmt.Sprintf("content blocked: similarity score %.2f exceeds threshold %.2f",
				maxScore,
				cfg.Threshold,
			)),
		)
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
	keywords []string,
	regexRules []*regexp.Regexp,
) bool {
	if len(inputBody) == 0 {
		return false
	}

	startTime := time.Now()

	content := string(inputBody)
	threshold := cfg.SimilarityThreshold
	if threshold == 0 {
		threshold = 0.8
	}

	if foundWord, keyword, similarity, found := p.findSimilarKeyword(content, threshold, keywords); found {
		latencyMs := time.Since(startTime).Milliseconds()
		if evt.KeyRegModeration != nil {
			evt.KeyRegModeration.DetectionLatencyMs = latencyMs
			evt.KeyRegModeration.Reason = KeyRegReason{
				Type:    "keyword",
				Pattern: keyword,
				Match:   foundWord,
				Score:   similarity,
			}
		}
		p.sendError(
			firewallErrors,
			NewModerationViolation(
				fmt.Sprintf("content blocked: word '%s' is similar to blocked keyword '%s' (score: %.2f)",
					foundWord,
					keyword,
					similarity,
				),
			),
		)
		return true
	}

	for _, pattern := range regexRules {
		matches := pattern.FindStringSubmatch(content)
		if len(matches) > 0 {
			latencyMs := time.Since(startTime).Milliseconds()
			if evt.KeyRegModeration != nil {
				evt.KeyRegModeration.DetectionLatencyMs = latencyMs
				evt.KeyRegModeration.Reason = KeyRegReason{
					Type:    "regex",
					Pattern: pattern.String(),
					Match:   matches[0],
				}
			}
			p.sendError(
				firewallErrors,
				NewModerationViolation(fmt.Sprintf("content blocked: regex pattern %s found in request body", pattern)),
			)
			return true
		}
	}

	latencyMs := time.Since(startTime).Milliseconds()
	if evt.KeyRegModeration != nil {
		evt.KeyRegModeration.DetectionLatencyMs = latencyMs
	}

	return false
}

// local helpers removed in favor of pluginutils.DefineRequestBody

func (p *NeuralTrustModerationPlugin) levenshteinDistance(s1, s2 string) int {
	s1 = strings.ToLower(s1)
	s2 = strings.ToLower(s2)

	m := len(s1)
	n := len(s2)
	if m == 0 {
		return n
	}
	if n == 0 {
		return m
	}

	// For extremely large inputs, avoid excessive allocations and potential overflows.
	// Words for moderation should be reasonably small; if not, treat as maximally distant.
	const maxWordLen = 4096
	if m > maxWordLen || n > maxWordLen {
		if m > n {
			return m
		}
		return n
	}

	// Ensure n <= m to minimize memory usage (only O(n) memory).
	if n > m {
		s1, s2 = s2, s1
		m, n = n, m
	}

	prev := make([]int, n+1)
	curr := make([]int, n+1)
	for j := 0; j <= n; j++ {
		prev[j] = j
	}

	for i := 1; i <= m; i++ {
		curr[0] = i
		c1 := s1[i-1]
		for j := 1; j <= n; j++ {
			cost := 1
			if c1 == s2[j-1] {
				cost = 0
			}
			// min of: deletion (prev[j]+1), insertion (curr[j-1]+1), substitution (prev[j-1]+cost)
			deletion := prev[j] + 1
			insertion := curr[j-1] + 1
			subst := prev[j-1] + cost
			if deletion < insertion {
				if deletion < subst {
					curr[j] = deletion
				} else {
					curr[j] = subst
				}
			} else {
				if insertion < subst {
					curr[j] = insertion
				} else {
					curr[j] = subst
				}
			}
		}
		prev, curr = curr, prev
	}
	return prev[n]
}

func (p *NeuralTrustModerationPlugin) calculateSimilarity(s1, s2 string) float64 {
	distance := p.levenshteinDistance(s1, s2)
	maxLen := float64(max(len(s1), len(s2)))
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - float64(distance)/maxLen
}

func (p *NeuralTrustModerationPlugin) findSimilarKeyword(text string, threshold float64, keywords []string) (string, string, float64, bool) {
	words := strings.Fields(text)
	for _, word := range words {
		for _, keyword := range keywords {
			similarity := p.calculateSimilarity(word, keyword)
			if similarity >= threshold {
				return word, keyword, similarity, true
			}
		}
	}
	return "", "", 0, false
}
