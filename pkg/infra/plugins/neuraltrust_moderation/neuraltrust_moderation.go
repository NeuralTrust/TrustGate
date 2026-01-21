package neuraltrust_moderation

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/infra/firewall"
	"github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/pluginiface"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/infra/pluginutils"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	providersFactory "github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

const (
	PluginName = "neuraltrust_moderation"
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
	providerLocator    providersFactory.ProviderLocator
	firewallFactory    firewall.ClientFactory
	bufferPool         sync.Pool
	byteSlicePool      sync.Pool
}

func NewNeuralTrustModerationPlugin(
	logger *logrus.Logger,
	client httpx.Client,
	fingerPrintManager fingerprint.Tracker,
	providerLocator providersFactory.ProviderLocator,
	firewallFactory firewall.ClientFactory,
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
		providerLocator:    providerLocator,
		firewallFactory:    firewallFactory,
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

func (p *NeuralTrustModerationPlugin) Stages() []pluginTypes.Stage {
	return []pluginTypes.Stage{pluginTypes.PreRequest}
}

func (p *NeuralTrustModerationPlugin) AllowedStages() []pluginTypes.Stage {
	return []pluginTypes.Stage{pluginTypes.PreRequest}
}

func (p *NeuralTrustModerationPlugin) ValidateConfig(config pluginTypes.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
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

	llmEnabled := cfg.LLMParamBag != nil && cfg.LLMParamBag.Enabled
	ntTopicEnabled := cfg.NTTopicParamBag != nil && cfg.NTTopicParamBag.Enabled

	// LLM and NTTopicModeration are mutually exclusive
	if llmEnabled && ntTopicEnabled {
		return fmt.Errorf("llm_moderation and nt_topic_moderation cannot be enabled at the same time; choose one")
	}

	if llmEnabled {
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

	if ntTopicEnabled {
		if cfg.NTTopicParamBag.Credentials == nil || cfg.NTTopicParamBag.Credentials.BaseURL == "" {
			return fmt.Errorf("nt_topic_moderation requires credentials.base_url")
		}
		if cfg.NTTopicParamBag.Credentials.Token == "" {
			return fmt.Errorf("nt_topic_moderation requires credentials.token")
		}
		if len(cfg.NTTopicParamBag.Topics) == 0 {
			return fmt.Errorf("nt_topic_moderation topics must be specified")
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

func (p *NeuralTrustModerationPlugin) Execute(
	ctx context.Context,
	cfg pluginTypes.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	evtCtx *metrics.EventContext,
) (*pluginTypes.PluginResponse, error) {
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

	var inputBytes []byte
	if len(req.Messages) > 0 {
		inputBytes = []byte(strings.Join(req.Messages, "\n"))
	} else {
		inputBody := req.Body
		if req.Stage == pluginTypes.PostRequest {
			inputBody = resp.Body
		}

		mappingContent, err := pluginutils.DefineRequestBody(inputBody, conf.MappingField)
		if err != nil {
			p.logger.WithError(err).Error("failed to define request body")
			return nil, fmt.Errorf("failed to define request body: %w", err)
		}
		inputBytes = []byte(mappingContent.Input)
	}

	evt := &NeuralTrustModerationData{
		MappingField: conf.MappingField,
		InputLength:  len(inputBytes),
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

	if !keyRegFound && conf.NTTopicParamBag != nil && conf.NTTopicParamBag.Enabled {
		wg.Add(1)
		go p.callNTTopicModeration(
			ctx,
			conf,
			&wg,
			inputBytes,
			firewallErrors,
			evt,
			&evtMu,
		)
	}

	if !keyRegFound && conf.LLMParamBag != nil && conf.LLMParamBag.Enabled {
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
				return nil, &pluginTypes.PluginError{
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

	return &pluginTypes.PluginResponse{
		StatusCode: 200,
		Message:    "prompt content is safe",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body: nil,
	}, nil
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
	evt.LLMModeration = &LLMModeration{
		Blocked:            resp.Flagged,
		InstructionMatch:   resp.InstructionMatch,
		Topic:              resp.Topic,
		DetectionLatencyMs: int64(duration * 1000),
	}
	if evtMu != nil {
		evtMu.Unlock()
	}

	if resp.Flagged {
		p.sendError(firewallErrors, NewModerationViolation("content blocked"))
	}
}

func (p *NeuralTrustModerationPlugin) callNTTopicModeration(
	ctx context.Context,
	cfg Config,
	wg *sync.WaitGroup,
	inputBody []byte,
	firewallErrors chan<- error,
	evt *NeuralTrustModerationData,
	evtMu *sync.Mutex,
) {
	defer wg.Done()

	if len(inputBody) == 0 {
		return
	}

	start := time.Now()

	client, err := p.firewallFactory.Get(firewall.ProviderNeuralTrust)
	if err != nil {
		p.logger.WithError(err).Error("failed to get neuraltrust firewall client")
		p.sendError(firewallErrors, err)
		return
	}

	content := firewall.ModerationContent{
		Input:      []string{string(inputBody)},
		Topics:     cfg.NTTopicParamBag.Topics,
		Thresholds: cfg.NTTopicParamBag.Thresholds,
	}

	creds := firewall.Credentials{
		NeuralTrustCredentials: firewall.NeuralTrustCredentials{
			BaseURL: cfg.NTTopicParamBag.Credentials.BaseURL,
			Token:   cfg.NTTopicParamBag.Credentials.Token,
		},
	}

	responses, err := client.DetectModeration(ctx, content, creds)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		p.logger.WithError(err).Error("failed to call moderation service")
		p.sendError(firewallErrors, err)
		return
	}

	duration := time.Since(start)

	if len(responses) == 0 {
		return
	}

	resp := responses[0]

	p.logger.WithFields(logrus.Fields{
		"duration":       duration.Seconds(),
		"is_blocked":     resp.IsBlocked,
		"blocked_topics": resp.BlockedTopics,
	}).Info("NT topic moderation service responded successfully")

	topicScores := make(map[string]NTTopicScore)
	for topic, score := range resp.TopicScores {
		topicScores[topic] = NTTopicScore{
			Topic:       score.Topic,
			Probability: score.Probability,
			Blocked:     score.Blocked,
		}
	}

	if evtMu != nil {
		evtMu.Lock()
	}
	evt.NTTopicModeration = &NTTopicModeration{
		TopicScores:        topicScores,
		BlockedTopics:      resp.BlockedTopics,
		Warnings:           resp.Warnings,
		Blocked:            resp.IsBlocked,
		DetectionLatencyMs: duration.Milliseconds(),
	}
	if evtMu != nil {
		evtMu.Unlock()
	}

	if resp.IsBlocked {
		blockedTopicsStr := strings.Join(resp.BlockedTopics, ", ")
		p.sendError(
			firewallErrors,
			NewModerationViolation(fmt.Sprintf("content blocked: topics [%s] exceeded threshold", blockedTopicsStr)),
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
