package neuraltrust_moderation

import (
	"context"
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
	PluginName             = "neuraltrust_moderation"
	maxModerationInputSize = 10 * 1024 * 1024 // 10 MB
)

type LLMResponse struct {
	Topic            string `json:"topic"`
	InstructionMatch string `json:"instruction_match"`
	Flagged          bool   `json:"flagged"`
}

type NeuralTrustModerationPlugin struct {
	basePlugin         *pluginTypes.BasePlugin
	fingerPrintManager fingerprint.Tracker
	logger             *logrus.Logger
	providerLocator    providersFactory.ProviderLocator
	firewallFactory    firewall.ClientFactory
}

var (
	regexCacheMu sync.RWMutex
	regexCache   = make(map[string][]*regexp.Regexp)
)

type levPair struct {
	a, b []int
}

var levPairPool = sync.Pool{
	New: func() any {
		return &levPair{
			a: make([]int, 0, 128),
			b: make([]int, 0, 128),
		}
	},
}

func NewNeuralTrustModerationPlugin(
	logger *logrus.Logger,
	fingerPrintManager fingerprint.Tracker,
	providerLocator providersFactory.ProviderLocator,
	firewallFactory firewall.ClientFactory,
) pluginiface.Plugin {
	return &NeuralTrustModerationPlugin{
		basePlugin:         pluginTypes.NewBasePlugin(),
		logger:             logger,
		fingerPrintManager: fingerPrintManager,
		providerLocator:    providerLocator,
		firewallFactory:    firewallFactory,
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
	if err := p.basePlugin.ValidateMode(cfg.Mode); err != nil {
		return err
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
	if conf.Mode == "" {
		conf.Mode = pluginTypes.ModeEnforce
	}

	inputBytes, err := p.resolveInput(req, resp, conf.MappingField)
	if err != nil {
		return nil, err
	}
	if len(inputBytes) > maxModerationInputSize {
		inputBytes = inputBytes[:maxModerationInputSize]
	}

	evt := &NeuralTrustModerationData{
		MappingField: conf.MappingField,
		InputLength:  len(inputBytes),
		Mode:         conf.Mode,
	}

	firewallErrors := make(chan error, 1)
	var wg sync.WaitGroup
	var evtMu sync.Mutex

	if conf.KeyRegParamBag != nil && conf.KeyRegParamBag.Enabled {
		found, err := p.executeKeyReg(ctx, conf, inputBytes, firewallErrors, evt)
		if err != nil {
			return nil, err
		}
		if found {
			if err := <-firewallErrors; err != nil {
				return p.handleViolation(ctx, conf, err, evt, evtCtx, cancel)
			}
		}
	}

	if !evt.Blocked {
		if conf.NTTopicParamBag != nil && conf.NTTopicParamBag.Enabled {
			wg.Add(1)
			go p.callNTTopicModeration(ctx, conf.NTTopicParamBag, &wg, inputBytes, firewallErrors, evt, &evtMu)
		}
		if conf.LLMParamBag != nil && conf.LLMParamBag.Enabled {
			wg.Add(1)
			go p.callAIModeration(ctx, conf.LLMParamBag, &wg, inputBytes, firewallErrors, evt, &evtMu)
		}
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
		close(firewallErrors)
	}()

	select {
	case err, ok := <-firewallErrors:
		if ok && err != nil {
			evt.Blocked = true
			return p.handleViolation(ctx, conf, err, evt, evtCtx, cancel)
		}
	case <-done:
	case <-ctx.Done():
		evtCtx.SetExtras(evt)
		return nil, ctx.Err()
	}

	evtCtx.SetExtras(evt)
	return safeResponse(), nil
}

func (p *NeuralTrustModerationPlugin) resolveInput(
	req *types.RequestContext,
	resp *types.ResponseContext,
	mappingField string,
) ([]byte, error) {
	if len(req.Messages) > 0 {
		return []byte(strings.Join(req.Messages, "\n")), nil
	}
	var body []byte
	if req.Stage == pluginTypes.PostRequest && resp != nil {
		body = resp.Body
	} else {
		body = req.Body
	}
	content, err := pluginutils.DefineRequestBody(body, mappingField, false)
	if err != nil {
		p.logger.WithError(err).Error("failed to define request body")
		return nil, fmt.Errorf("failed to define request body: %w", err)
	}
	return []byte(content.Input), nil
}

func (p *NeuralTrustModerationPlugin) executeKeyReg(
	ctx context.Context,
	conf Config,
	inputBytes []byte,
	firewallErrors chan<- error,
	evt *NeuralTrustModerationData,
) (bool, error) {
	keywords := conf.KeyRegParamBag.Keywords
	regexRules, err := getOrCompileRegex(conf.KeyRegParamBag.Regex)
	if err != nil {
		p.logger.WithError(err).Error("failed to compile regex pattern")
		return false, err
	}

	threshold := conf.KeyRegParamBag.SimilarityThreshold
	if threshold == 0 {
		threshold = 0.8
	}
	evt.KeyRegModeration = &KeyRegModeration{
		SimilarityThreshold: threshold,
	}

	found := p.callKeyRegModeration(ctx, conf.KeyRegParamBag, inputBytes, firewallErrors, evt, keywords, regexRules)
	if found {
		evt.Blocked = true
		evt.KeyRegModeration.Blocked = true
	}
	return found, nil
}

func (p *NeuralTrustModerationPlugin) handleViolation(
	ctx context.Context,
	conf Config,
	err error,
	evt *NeuralTrustModerationData,
	evtCtx *metrics.EventContext,
	cancel context.CancelFunc,
) (*pluginTypes.PluginResponse, error) {
	p.notifyGuardrailViolation(ctx, conf)
	cancel()
	if modErr, ok := errors.AsType[*moderationViolationError](err); ok {
		evtCtx.SetError(modErr)
		evtCtx.SetExtras(evt)
		if conf.Mode == pluginTypes.ModeObserve {
			return &pluginTypes.PluginResponse{
				StatusCode: 200,
				Message:    "prompt flagged",
				Headers: map[string][]string{
					"Content-Type": {"application/json"},
				},
			}, nil
		}
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

func safeResponse() *pluginTypes.PluginResponse {
	return &pluginTypes.PluginResponse{
		StatusCode: 200,
		Message:    "prompt content is safe",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
	}
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
		ttl := 60 * time.Second
		if conf.RetentionPeriod > 0 {
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

	// Build request body as JSON (replaces the old client.Ask call).
	userContent := providers.FormatInstructions(cfg.Instructions) + "\n[Input]\n" + string(inputBody)
	reqBody, marshalErr := json.Marshal(map[string]interface{}{
		"model": cfg.Model,
		"messages": []map[string]interface{}{
			{"role": "system", "content": SystemPrompt},
			{"role": "user", "content": userContent},
		},
		"max_tokens":  maxTokens,
		"temperature": 0.0,
	})
	if marshalErr != nil {
		p.logger.WithError(marshalErr).Error("failed to build llm request body")
		p.sendError(firewallErrors, marshalErr)
		return
	}

	responseBody, err := client.Completions(ctx, &providers.Config{
		Credentials: providersCreds,
		Model:       cfg.Model,
	}, reqBody)
	duration := time.Since(start).Seconds()
	if err != nil {
		latencyMs := time.Since(start).Milliseconds()
		if errors.Is(err, context.Canceled) {
			evtMu.Lock()
			evt.LLMModeration = &LLMModeration{
				Cancelled:          true,
				DetectionLatencyMs: latencyMs,
			}
			evtMu.Unlock()
			return
		}
		evtMu.Lock()
		evt.LLMModeration = &LLMModeration{
			DetectionLatencyMs: latencyMs,
		}
		evtMu.Unlock()
		p.logger.WithError(err).Error("failed to call llm provider")
		p.sendError(firewallErrors, err)
		return
	}

	if len(responseBody) == 0 {
		err := errors.New("LLM provider returned empty response")
		p.logger.WithError(err).Error("empty response from LLM provider")
		p.sendError(firewallErrors, err)
		return
	}

	p.logger.WithField("duration", duration).Debug("LLM provider responded successfully")

	// Parse the provider's raw JSON response to extract the text content.
	textContent, parseErr := extractTextFromProviderResponse(responseBody)
	if parseErr != nil {
		p.logger.WithError(parseErr).Error("failed to parse llm response")
		p.sendError(firewallErrors, parseErr)
		return
	}

	if textContent == "" {
		parseErr = errors.New("LLM provider returned empty text content")
		p.logger.WithError(parseErr).Error("empty text content from LLM response")
		p.sendError(firewallErrors, parseErr)
		return
	}

	var resp LLMResponse
	if err := json.Unmarshal([]byte(textContent), &resp); err != nil {
		p.logger.WithError(err).Error("failed to unmarshal llm response")
		p.sendError(firewallErrors, err)
		return
	}

	evtMu.Lock()
	evt.LLMModeration = &LLMModeration{
		Blocked:            resp.Flagged,
		InstructionMatch:   resp.InstructionMatch,
		Topic:              resp.Topic,
		DetectionLatencyMs: int64(duration * 1000),
	}
	evtMu.Unlock()

	if resp.Flagged {
		p.sendError(firewallErrors, NewModerationViolation("content blocked"))
	}
}

func (p *NeuralTrustModerationPlugin) callNTTopicModeration(
	ctx context.Context,
	cfg *NTTopicParamBag,
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

	responses, err := client.DetectModeration(ctx, firewall.ModerationContent{
		Input:      []string{string(inputBody)},
		Topics:     cfg.Topics,
		Thresholds: cfg.Thresholds,
	}, firewall.Credentials{
		NeuralTrustCredentials: firewall.NeuralTrustCredentials{
			BaseURL: cfg.Credentials.BaseURL,
			Token:   cfg.Credentials.Token,
		},
	})
	duration := time.Since(start)

	if err != nil {
		latencyMs := duration.Milliseconds()
		if errors.Is(err, context.Canceled) {
			evtMu.Lock()
			evt.NTTopicModeration = &NTTopicModeration{
				Cancelled:          true,
				DetectionLatencyMs: latencyMs,
			}
			evtMu.Unlock()
			return
		}
		evtMu.Lock()
		evt.NTTopicModeration = &NTTopicModeration{
			DetectionLatencyMs: latencyMs,
		}
		evtMu.Unlock()
		p.logger.WithError(err).Error("failed to call moderation service")
		p.sendError(firewallErrors, err)
		return
	}

	if len(responses) == 0 {
		evtMu.Lock()
		evt.NTTopicModeration = &NTTopicModeration{
			DetectionLatencyMs: duration.Milliseconds(),
		}
		evtMu.Unlock()
		return
	}

	resp := responses[0]

	p.logger.WithFields(logrus.Fields{
		"duration":       duration.Seconds(),
		"is_blocked":     resp.IsBlocked,
		"blocked_topics": resp.BlockedTopics,
	}).Info("NT topic moderation service responded successfully")

	topicScores := make(map[string]NTTopicScore, len(resp.TopicScores))
	for topic, score := range resp.TopicScores {
		topicScores[topic] = NTTopicScore{
			Topic:       score.Topic,
			Probability: score.Probability,
			Blocked:     score.Blocked,
		}
	}

	evtMu.Lock()
	evt.NTTopicModeration = &NTTopicModeration{
		TopicScores:        topicScores,
		BlockedTopics:      resp.BlockedTopics,
		Warnings:           resp.Warnings,
		Blocked:            resp.IsBlocked,
		DetectionLatencyMs: duration.Milliseconds(),
	}
	evtMu.Unlock()

	if resp.IsBlocked {
		p.sendError(
			firewallErrors,
			NewModerationViolation(fmt.Sprintf("content blocked: topics [%s] exceeded threshold", strings.Join(resp.BlockedTopics, ", "))),
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
				fmt.Sprintf("content blocked: word %q is similar to blocked keyword %q (score: %.2f)",
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

func getOrCompileRegex(patterns []string) ([]*regexp.Regexp, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	key := strings.Join(patterns, "\x00")

	regexCacheMu.RLock()
	if cached, ok := regexCache[key]; ok {
		regexCacheMu.RUnlock()
		return cached, nil
	}
	regexCacheMu.RUnlock()

	regexCacheMu.Lock()
	defer regexCacheMu.Unlock()

	if cached, ok := regexCache[key]; ok {
		return cached, nil
	}

	compiled := make([]*regexp.Regexp, len(patterns))
	for i, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regex pattern '%s': %v", pattern, err)
		}
		compiled[i] = re
	}

	regexCache[key] = compiled
	return compiled, nil
}

func (p *NeuralTrustModerationPlugin) levenshteinDistance(s1, s2 string) int {
	const maxWordLen = 4096
	if len(s1) > maxWordLen {
		s1 = s1[:maxWordLen]
	}
	if len(s2) > maxWordLen {
		s2 = s2[:maxWordLen]
	}

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

	if n > m {
		s1, s2 = s2, s1
		m, n = n, m
	}

	if n > maxWordLen {
		n = maxWordLen
	}

	// Bounded size visible at allocation site so static analysis can verify
	// that n+1 cannot overflow. n is guaranteed <= maxWordLen (4096).
	size := n + 1
	if size < 0 || size > maxWordLen+1 {
		return max(m, n)
	}

	pair := levPairPool.Get().(*levPair)
	prev := pair.a
	curr := pair.b
	if cap(prev) < size {
		prev = make([]int, size)
	} else {
		prev = prev[:size]
	}
	if cap(curr) < size {
		curr = make([]int, size)
	} else {
		curr = curr[:size]
	}

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

	result := prev[n]
	pair.a = prev
	pair.b = curr
	levPairPool.Put(pair)
	return result
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

// extractTextFromProviderResponse extracts the assistant's text content from a
// raw provider JSON response. It supports both OpenAI chat completion format
// (choices[0].message.content) and Anthropic messages format (content[0].text).
func extractTextFromProviderResponse(body []byte) (string, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return "", fmt.Errorf("invalid JSON response: %w", err)
	}

	// Try OpenAI format: choices[0].message.content
	if choices, ok := raw["choices"].([]interface{}); ok && len(choices) > 0 {
		choice, ok := choices[0].(map[string]interface{})
		if ok {
			if msg, ok := choice["message"].(map[string]interface{}); ok {
				if content, ok := msg["content"].(string); ok {
					content = strings.TrimPrefix(content, "```json")
					content = strings.TrimSuffix(content, "```")
					content = strings.TrimSpace(content)
					return content, nil
				}
			}
		}
	}

	// Try Anthropic format: content[0].text
	if blocks, ok := raw["content"].([]interface{}); ok && len(blocks) > 0 {
		block, ok := blocks[0].(map[string]interface{})
		if ok {
			if text, ok := block["text"].(string); ok {
				text = strings.TrimPrefix(text, "```json")
				text = strings.TrimSuffix(text, "```")
				text = strings.TrimSpace(text)
				return text, nil
			}
		}
	}

	return "", fmt.Errorf("unable to extract text from provider response")
}
