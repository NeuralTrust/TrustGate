package data_masking

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/pluginiface"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/infra/pluginutils"
	"github.com/NeuralTrust/TrustGate/pkg/pii_entities"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

const (
	PluginName          = "data_masking"
	DefaultMaskChar     = "*"
	SimilarityThreshold = 0.8
)

type hashToOriginalMap map[string]string

type DataMaskingPlugin struct {
	logger      *logrus.Logger
	memoryCache *cache.TTLMap
}

type ReversibleHashingConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Secret  string `mapstructure:"secret"` // #nosec G117 -- Config field for reversible hashing secret
}

type Config struct {
	ReversibleHashing   ReversibleHashingConfig `mapstructure:"reversible_hashing"`
	Rules               []Rule                  `mapstructure:"rules"`
	SimilarityThreshold float64                 `mapstructure:"similarity_threshold"`
	PredefinedEntities  []EntityConfig          `mapstructure:"predefined_entities"`
	ApplyAll            bool                    `mapstructure:"apply_all"`
	MaxEditDistance     int                     `mapstructure:"max_edit_distance"`
	NormalizeInput      bool                    `mapstructure:"normalize_input"`
	MappingField        string                  `mapstructure:"mapping_field"`
}

type EntityConfig struct {
	Entity      string `mapstructure:"entity"`
	Enabled     bool   `mapstructure:"enabled"`
	MaskWith    string `mapstructure:"mask_with"`
	PreserveLen bool   `mapstructure:"preserve_len"`
}

type Rule struct {
	Pattern     string `mapstructure:"pattern"`
	Type        string `mapstructure:"type"` // "keyword" or "regex"
	MaskWith    string `mapstructure:"mask_with"`
	PreserveLen bool   `mapstructure:"preserve_len"`
}

func NewDataMaskingPlugin(logger *logrus.Logger, c cache.Client) pluginiface.Plugin {
	var ttl *cache.TTLMap
	if c != nil {
		ttl = c.GetTTLMap(cache.DataMaskingTTLName)
	}
	if ttl == nil {
		ttl = cache.NewTTLMap(10 * time.Minute)
	}
	return &DataMaskingPlugin{
		logger:      logger,
		memoryCache: ttl,
	}
}

func (p *DataMaskingPlugin) Name() string { return PluginName }

func (p *DataMaskingPlugin) RequiredPlugins() []string { return nil }

func (p *DataMaskingPlugin) Stages() []pluginTypes.Stage { return nil }

func (p *DataMaskingPlugin) AllowedStages() []pluginTypes.Stage {
	return []pluginTypes.Stage{pluginTypes.PreRequest, pluginTypes.PreResponse, pluginTypes.PostResponse}
}

func (p *DataMaskingPlugin) ValidateConfig(config pluginTypes.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %v", err)
	}

	if len(cfg.Rules) == 0 && len(cfg.PredefinedEntities) == 0 && !cfg.ApplyAll {
		return fmt.Errorf("at least one rule or predefined entity must be specified")
	}

	for _, rule := range cfg.Rules {
		if rule.Type != "keyword" && rule.Type != "regex" {
			return fmt.Errorf("invalid rule type '%s': must be 'keyword' or 'regex'", rule.Type)
		}
		if rule.Type == "regex" {
			if _, err := regexp.Compile(rule.Pattern); err != nil {
				return fmt.Errorf("invalid regex pattern '%s': %v", rule.Pattern, err)
			}
		}
		if rule.MaskWith == "" {
			return fmt.Errorf("mask_with value must be specified for each rule")
		}
	}

	if !cfg.ApplyAll && len(cfg.PredefinedEntities) > 0 {
		for _, entity := range cfg.PredefinedEntities {
			if !pii_entities.IsValid(entity.Entity) {
				return fmt.Errorf("invalid predefined entity type: %s", entity.Entity)
			}
		}
	}

	if cfg.ReversibleHashing.Enabled && cfg.ReversibleHashing.Secret == "" {
		return fmt.Errorf("reversible_hashing.secret must be set when reversible_hashing is enabled")
	}

	return nil
}

// executionContext holds shared state for a single Execute call, avoiding
// repeated parameter passing across the three execution paths.
type executionContext struct {
	ctx    context.Context
	cfg    pluginTypes.PluginConfig
	config Config
	rules  maskingRules
	events []MaskingEvent
}

func (p *DataMaskingPlugin) Execute(
	ctx context.Context,
	cfg pluginTypes.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	evtCtx *metrics.EventContext,
) (*pluginTypes.PluginResponse, error) {
	var config Config
	if err := mapstructure.Decode(cfg.Settings, &config); err != nil {
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}

	if config.SimilarityThreshold == 0 {
		config.SimilarityThreshold = SimilarityThreshold
	}
	if config.MaxEditDistance == 0 {
		config.MaxEditDistance = 1
	}

	if p.memoryCache == nil {
		p.memoryCache = cache.NewTTLMap(10 * time.Minute)
	}

	ec := &executionContext{
		ctx:    ctx,
		cfg:    cfg,
		config: config,
		rules:  p.buildRules(config),
	}

	p.initHashMapIfNeeded(ec)

	var err error
	switch {
	case req.Provider != "":
		err = p.executeProvider(ec, req, resp)
	case config.MappingField != "":
		err = p.executeWithMapping(ec, req, resp)
	default:
		err = p.executeFullBody(ec, req, resp)
	}
	if err != nil {
		return nil, err
	}

	evtCtx.SetExtras(DataMaskingData{
		Masked: len(ec.events) > 0,
		Events: ec.events,
	})
	return &pluginTypes.PluginResponse{
		StatusCode: 200,
		Message:    "Content masked successfully",
	}, nil
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func (p *DataMaskingPlugin) initHashMapIfNeeded(ec *executionContext) {
	if ec.config.ReversibleHashing.Enabled && ec.cfg.Stage == pluginTypes.PreRequest {
		if traceId, ok := ec.ctx.Value(common.TraceIdKey).(string); ok && p.memoryCache != nil {
			p.memoryCache.Set(traceId, make(hashToOriginalMap))
		}
	}
}

// maskText is the single entry point for masking a plain-text string using the
// current execution's rules. It returns the masked text and any masking events.
func (p *DataMaskingPlugin) maskText(ec *executionContext, text string) (string, []MaskingEvent) {
	return p.maskPlainTextWithRules(
		text,
		ec.config.SimilarityThreshold, ec.config,
		ec.rules.keywords, ec.rules.regexRules,
	)
}

// applyReversibleHashing replaces mask placeholders with HMAC hashes in the
// masked text and accumulates the hash→original mapping. Returns the updated
// text with hashes instead of mask placeholders.
func applyReversibleHashing(config Config, masked string, events []MaskingEvent, hashMap hashToOriginalMap) string {
	for i := range events {
		hash := generateReversibleHash(config.ReversibleHashing.Secret, events[i].OriginalValue)
		events[i].ReversibleKey = hash
		hashMap[hash] = events[i].OriginalValue
		masked = strings.ReplaceAll(masked, events[i].MaskedWith, hash)
	}
	return masked
}

func (p *DataMaskingPlugin) storeHashMap(ec *executionContext, hashMap hashToOriginalMap) {
	if len(hashMap) == 0 {
		return
	}
	if traceId, ok := ec.ctx.Value(common.TraceIdKey).(string); ok && p.memoryCache != nil {
		p.memoryCache.Set(traceId, hashMap)
	}
}

func (p *DataMaskingPlugin) loadHashMap(ctx context.Context) hashToOriginalMap {
	traceId, ok := ctx.Value(common.TraceIdKey).(string)
	if !ok || p.memoryCache == nil {
		return nil
	}
	if value, exists := p.memoryCache.Get(traceId); exists {
		if hm, ok := value.(hashToOriginalMap); ok {
			return hm
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Provider path
// ---------------------------------------------------------------------------

func (p *DataMaskingPlugin) executeProvider(
	ec *executionContext,
	req *types.RequestContext,
	resp *types.ResponseContext,
) error {
	switch ec.cfg.Stage {
	case pluginTypes.PreRequest:
		canonical, err := req.CanonicalRequest()
		if err != nil {
			p.logger.WithError(err).Warn("failed to decode canonical request, falling back to full body")
			return p.executeFullBody(ec, req, resp)
		}
		if canonical == nil {
			return p.executeFullBody(ec, req, resp)
		}

		hashMap := make(hashToOriginalMap)
		for i := range canonical.Messages {
			if canonical.Messages[i].Content == "" {
				continue
			}
			masked, events := p.maskText(ec, canonical.Messages[i].Content)
			if ec.config.ReversibleHashing.Enabled {
				masked = applyReversibleHashing(ec.config, masked, events, hashMap)
			}
			canonical.Messages[i].Content = masked
			ec.events = append(ec.events, events...)
		}

		if canonical.System != "" {
			masked, events := p.maskText(ec, canonical.System)
			if ec.config.ReversibleHashing.Enabled {
				masked = applyReversibleHashing(ec.config, masked, events, hashMap)
			}
			canonical.System = masked
			ec.events = append(ec.events, events...)
		}

		if ec.config.ReversibleHashing.Enabled {
			p.storeHashMap(ec, hashMap)
		}

		a, err := req.SourceAdapter()
		if err != nil || a == nil {
			return fmt.Errorf("failed to resolve source adapter: %w", err)
		}
		newBody, err := a.EncodeRequest(canonical)
		if err != nil {
			return fmt.Errorf("failed to re-encode masked request: %w", err)
		}
		req.Body = newBody

	case pluginTypes.PreResponse:
		canonical, err := resp.CanonicalResponse()
		if err != nil {
			p.logger.WithError(err).Warn("failed to decode canonical response, falling back to full body")
			return p.executeFullBody(ec, req, resp)
		}
		if canonical == nil {
			return p.executeFullBody(ec, req, resp)
		}

		if canonical.Content != "" {
			masked, events := p.maskText(ec, canonical.Content)
			canonical.Content = masked
			ec.events = append(ec.events, events...)
		}

		a, err := req.SourceAdapter()
		if err != nil || a == nil {
			return fmt.Errorf("failed to resolve source adapter: %w", err)
		}
		newBody, err := a.EncodeResponse(canonical)
		if err != nil {
			return fmt.Errorf("failed to re-encode masked response: %w", err)
		}
		resp.Body = newBody

	case pluginTypes.PostResponse:
		if !ec.config.ReversibleHashing.Enabled {
			return nil
		}
		hashMap := p.loadHashMap(ec.ctx)
		if len(hashMap) == 0 {
			return nil
		}
		canonical, err := resp.CanonicalResponse()
		if err != nil || canonical == nil {
			return p.executeFullBody(ec, req, resp)
		}
		if canonical.Content != "" {
			for hash, original := range hashMap {
				canonical.Content = strings.ReplaceAll(canonical.Content, hash, original)
			}
		}
		a, err := req.SourceAdapter()
		if err != nil || a == nil {
			return fmt.Errorf("failed to resolve source adapter: %w", err)
		}
		newBody, err := a.EncodeResponse(canonical)
		if err != nil {
			return fmt.Errorf("failed to re-encode restored response: %w", err)
		}
		resp.Body = newBody
	}

	return nil
}

// ---------------------------------------------------------------------------
// Mapping-field path
// ---------------------------------------------------------------------------

func (p *DataMaskingPlugin) executeWithMapping(
	ec *executionContext,
	req *types.RequestContext,
	resp *types.ResponseContext,
) error {
	maskExtracted := func(body []byte) ([]byte, []MaskingEvent, error) {
		content, err := pluginutils.DefineRequestBody(body, ec.config.MappingField, true)
		if err != nil || content.Input == "" {
			return body, nil, nil
		}
		masked, events := p.maskText(ec, content.Input)
		if masked == content.Input {
			return body, events, nil
		}
		result := strings.Replace(string(body), content.Input, masked, 1)
		return []byte(result), events, nil
	}

	if req != nil && len(req.Body) > 0 && ec.cfg.Stage == pluginTypes.PreRequest {
		maskedBody, events, err := maskExtracted(req.Body)
		if err != nil {
			return err
		}
		if ec.config.ReversibleHashing.Enabled {
			hashMap := make(hashToOriginalMap)
			for i := range events {
				hash := generateReversibleHash(ec.config.ReversibleHashing.Secret, events[i].OriginalValue)
				events[i].ReversibleKey = hash
				hashMap[hash] = events[i].OriginalValue
			}
			p.storeHashMap(ec, hashMap)
		}
		req.Body = maskedBody
		ec.events = append(ec.events, events...)
	}

	if resp != nil && len(resp.Body) > 0 && (ec.cfg.Stage == pluginTypes.PreResponse || ec.cfg.Stage == pluginTypes.PostResponse) {
		if ec.config.ReversibleHashing.Enabled && ec.cfg.Stage == pluginTypes.PostResponse {
			hashMap := p.loadHashMap(ec.ctx)
			if len(hashMap) > 0 {
				content := string(resp.Body)
				for hash, original := range hashMap {
					content = strings.ReplaceAll(content, hash, original)
				}
				resp.Body = []byte(content)
			}
		} else {
			maskedBody, events, err := maskExtracted(resp.Body)
			if err != nil {
				return err
			}
			resp.Body = maskedBody
			ec.events = append(ec.events, events...)
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Full-body path (original recursive masking)
// ---------------------------------------------------------------------------

func (p *DataMaskingPlugin) executeFullBody(
	ec *executionContext,
	req *types.RequestContext,
	resp *types.ResponseContext,
) error {
	hashMap := make(hashToOriginalMap)
	secret := ec.config.ReversibleHashing.Secret

	if ec.config.ReversibleHashing.Enabled && ec.cfg.Stage == pluginTypes.PostResponse {
		hashMap = p.loadHashMap(ec.ctx)
	}

	processBody := func(body []byte, isRequest bool) ([]byte, error) {
		var jsonData interface{}
		if err := json.Unmarshal(body, &jsonData); err == nil {
			var maskedData interface{}
			var events []MaskingEvent

			if !isRequest && ec.cfg.Stage == pluginTypes.PostResponse && ec.config.ReversibleHashing.Enabled {
				maskedData = restoreFromHashes(jsonData, hashMap)
			} else {
				maskedData, events = p.maskJSONDataWithRules(jsonData, ec.config.SimilarityThreshold, ec.config, ec.rules.keywords, ec.rules.regexRules)

				if ec.config.ReversibleHashing.Enabled && isRequest && ec.cfg.Stage == pluginTypes.PreRequest {
					for i := range events {
						hash := generateReversibleHash(secret, events[i].OriginalValue)
						events[i].ReversibleKey = hash
						hashMap[hash] = events[i].OriginalValue
					}
					maskedData = replaceWithHashes(maskedData, events)
					p.storeHashMap(ec, hashMap)
				}
			}

			maskedJSON, err := json.Marshal(maskedData)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal masked JSON: %v", err)
			}
			ec.events = append(ec.events, events...)
			return maskedJSON, nil
		}

		content := string(body)
		var maskedContent string
		var events []MaskingEvent

		if !isRequest && ec.cfg.Stage == pluginTypes.PostResponse && ec.config.ReversibleHashing.Enabled {
			maskedContent = content
			for hash, original := range hashMap {
				maskedContent = strings.ReplaceAll(maskedContent, hash, original)
			}
		} else {
			maskedContent, events = p.maskText(ec, content)

			if ec.config.ReversibleHashing.Enabled && isRequest && ec.cfg.Stage == pluginTypes.PreRequest {
				for i := range events {
					hash := generateReversibleHash(secret, events[i].OriginalValue)
					events[i].ReversibleKey = hash
					hashMap[hash] = events[i].OriginalValue
					maskedContent = strings.ReplaceAll(maskedContent, events[i].MaskedWith, hash)
				}
				p.storeHashMap(ec, hashMap)
			}
		}

		ec.events = append(ec.events, events...)
		return []byte(maskedContent), nil
	}

	if req != nil && len(req.Body) > 0 {
		maskedBody, err := processBody(req.Body, true)
		if err != nil {
			return err
		}
		req.Body = maskedBody
	}

	if resp != nil && len(resp.Body) > 0 {
		maskedBody, err := processBody(resp.Body, false)
		if err != nil {
			return err
		}
		resp.Body = maskedBody
	}

	return nil
}

// ---------------------------------------------------------------------------
// Rule building & helpers
// ---------------------------------------------------------------------------

type maskingRules struct {
	keywords   map[string]string
	regexRules map[string]*regexp.Regexp
}

func (p *DataMaskingPlugin) buildRules(config Config) maskingRules {
	keywords := make(map[string]string)
	regexRules := make(map[string]*regexp.Regexp)

	if config.ApplyAll {
		for entityType, pattern := range pii_entities.Patterns {
			maskValue, exists := pii_entities.DefaultMasks[entityType]
			if !exists {
				maskValue = "[MASKED]"
			}
			regexRules[pattern.String()] = pattern
			keywords[pattern.String()] = maskValue
		}
	} else {
		for _, entity := range config.PredefinedEntities {
			if !entity.Enabled {
				continue
			}
			entityType := pii_entities.Entity(entity.Entity)
			pattern, exists := pii_entities.Patterns[entityType]
			if !exists {
				continue
			}
			maskValue := entity.MaskWith
			if maskValue == "" {
				maskValue = pii_entities.DefaultMasks[entityType]
			}
			regexRules[pattern.String()] = pattern
			keywords[pattern.String()] = maskValue
		}
	}

	for _, rule := range config.Rules {
		maskValue := rule.MaskWith
		if maskValue == "" {
			maskValue = DefaultMaskChar
		}
		switch rule.Type {
		case "keyword":
			keywords[rule.Pattern] = maskValue
		case "regex":
			regex, err := regexp.Compile(rule.Pattern)
			if err != nil {
				continue
			}
			regexRules[rule.Pattern] = regex
			keywords[rule.Pattern] = maskValue
		}
	}

	return maskingRules{keywords: keywords, regexRules: regexRules}
}

func generateReversibleHash(secret, value string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}

func replaceWithHashes(data interface{}, events []MaskingEvent) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{}, len(v))
		for key, value := range v {
			result[key] = replaceWithHashes(value, events)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, value := range v {
			result[i] = replaceWithHashes(value, events)
		}
		return result
	case string:
		result := v
		for _, event := range events {
			if event.ReversibleKey != "" && strings.Contains(result, event.MaskedWith) {
				result = strings.ReplaceAll(result, event.MaskedWith, event.ReversibleKey)
			}
		}
		return result
	default:
		return v
	}
}

func restoreFromHashes(data interface{}, hashMap hashToOriginalMap) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{}, len(v))
		for key, value := range v {
			result[key] = restoreFromHashes(value, hashMap)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, value := range v {
			result[i] = restoreFromHashes(value, hashMap)
		}
		return result
	case string:
		result := v
		for hash, original := range hashMap {
			if strings.Contains(result, hash) {
				result = strings.ReplaceAll(result, hash, original)
			}
		}
		return result
	default:
		return v
	}
}

func levenshteinDistance(s1, s2 string) int {
	// Cap input lengths to a reasonable bound to prevent excessive allocations.
	const maxLen = 10_000
	if len(s1) > maxLen {
		s1 = s1[:maxLen]
	}
	if len(s2) > maxLen {
		s2 = s2[:maxLen]
	}

	s1 = strings.ToLower(s1)
	s2 = strings.ToLower(s2)

	l1 := len(s1)
	l2 := len(s2)

	if l1 == 0 {
		return l2
	}
	if l2 == 0 {
		return l1
	}

	// Use O(min(l1,l2)) space dynamic programming to minimize allocations
	if l1 < l2 {
		// Ensure s1 is the longer string so l2 is used for the smaller dimension
		s1, s2 = s2, s1
		l1, l2 = l2, l1
	}

	// l2 <= maxLen (10 000) here, so l2+1 cannot overflow.
	previous := make([]int, l2+1)
	current := make([]int, l2+1)
	for j := 0; j <= l2; j++ {
		previous[j] = j
	}

	for i := 1; i <= l1; i++ {
		current[0] = i
		for j := 1; j <= l2; j++ {
			cost := 1
			if s1[i-1] == s2[j-1] {
				cost = 0
			}
			insertion := current[j-1] + 1
			deletion := previous[j] + 1
			substitution := previous[j-1] + cost
			current[j] = min3(insertion, deletion, substitution)
		}
		// swap previous and current
		previous, current = current, previous
	}
	return previous[l2]
}

func calculateSimilarity(s1, s2 string) float64 {
	distance := levenshteinDistance(s1, s2)
	m := float64(max2(len(s1), len(s2)))
	if m == 0 {
		return 1.0
	}
	return 1.0 - float64(distance)/m
}

func (p *DataMaskingPlugin) findSimilarKeyword(text string, threshold float64, keywords map[string]string, regexRules map[string]*regexp.Regexp) (string, string, bool) {
	for keyword, maskWith := range keywords {
		if _, exists := regexRules[keyword]; exists {
			continue
		}
		if strings.Contains(text, keyword) {
			return text, maskWith, true
		}
	}
	for keyword, maskWith := range keywords {
		if _, exists := regexRules[keyword]; exists {
			continue
		}
		similarity := calculateSimilarity(text, keyword)
		if similarity >= threshold {
			return text, maskWith, true
		}
	}
	return "", "", false
}

func (p *DataMaskingPlugin) maskContent(content string, maskWith string, preserveLen bool) string {
	if preserveLen {
		if len(maskWith) > 1 {
			return strings.Repeat(maskWith, 1)
		}
		return strings.Repeat("*", len(content))
	}
	return maskWith
}

func normalizeText(text string) string {
	text = strings.ToLower(text)
	text = strings.ReplaceAll(text, "-", "")
	text = strings.ReplaceAll(text, " ", "")
	text = strings.ReplaceAll(text, ".", "")
	text = strings.ReplaceAll(text, "/", "")
	return text
}

func (p *DataMaskingPlugin) maskPlainTextWithRules(
	content string,
	threshold float64,
	config Config,
	keywords map[string]string,
	regexRules map[string]*regexp.Regexp,
) (string, []MaskingEvent) {
	var events []MaskingEvent
	maskedContent := content

	if len(maskedContent) > 1<<20 {
		return maskedContent, events
	}

	enabledEntities := buildEnabledMap(config)
	matches := pii_entities.DetectAll(content, enabledEntities)

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Start < matches[j].Start
	})

	for _, m := range matches {
		maskValue := pii_entities.GetDefaultMask(m.Entity)
		if config.ApplyAll {
			maskValue = pii_entities.DefaultMasks[pii_entities.Default]
		}
		events = append(events, MaskingEvent{
			Entity:        string(m.Entity),
			OriginalValue: m.Value,
			MaskedWith:    maskValue,
		})
	}

	for i := len(matches) - 1; i >= 0; i-- {
		m := matches[i]
		maskValue := pii_entities.GetDefaultMask(m.Entity)
		if config.ApplyAll {
			maskValue = pii_entities.DefaultMasks[pii_entities.Default]
		}
		maskedContent = maskedContent[:m.Start] + maskValue + maskedContent[m.End:]
	}

	for pattern, regex := range regexRules {
		isPredefined := false
		for _, entityType := range pii_entities.DetectionOrder {
			if entityPattern, exists := pii_entities.Patterns[entityType]; exists {
				if entityPattern.String() == pattern {
					isPredefined = true
					break
				}
			}
		}
		if isPredefined {
			continue
		}

		matches := regex.FindAllString(maskedContent, -1)
		if len(matches) > 0 {
			maskValue := keywords[pattern]
			for _, match := range matches {
				events = append(events, MaskingEvent{
					Entity:        pattern,
					OriginalValue: match,
					MaskedWith:    maskValue,
				})
				maskedContent = strings.ReplaceAll(maskedContent, match, maskValue)
			}
		}
	}

	for keyword, maskValue := range keywords {
		if _, exists := regexRules[keyword]; exists {
			continue
		}
		if strings.Contains(maskedContent, keyword) {
			events = append(events, MaskingEvent{
				Entity:        keyword,
				OriginalValue: maskedContent,
				MaskedWith:    maskValue,
			})
			maskedContent = strings.ReplaceAll(maskedContent, keyword, maskValue)
		}
	}

	words := strings.Fields(maskedContent)
	modified := false
	for i, word := range words {
		if origWord, maskWith, found := p.findSimilarKeyword(word, threshold, keywords, regexRules); found {
			words[i] = p.maskContent(origWord, maskWith, true)
			modified = true
		}
	}
	if modified {
		maskedContent = strings.Join(words, " ")
	}

	return maskedContent, events
}

func (p *DataMaskingPlugin) generateVariants(word string, maxDistance int) []string {
	if maxDistance <= 0 || len(word) <= 3 {
		return []string{word}
	}

	variants := []string{word}

	for i := 0; i < len(word); i++ {
		variant := word[:i] + word[i+1:]
		variants = append(variants, variant)
	}

	for i := 0; i < len(word); i++ {
		substitutions := map[byte][]byte{
			'0': {'o', 'O'},
			'1': {'l', 'I'},
			'o': {'0'},
			'O': {'0'},
			'l': {'1', 'I'},
			'I': {'1', 'l'},
			's': {'5'},
			'S': {'5'},
			'5': {'s', 'S'},
			'a': {'@'},
			'@': {'a'},
		}
		if subs, ok := substitutions[word[i]]; ok {
			for _, sub := range subs {
				variant := word[:i] + string(sub) + word[i+1:]
				variants = append(variants, variant)
			}
		}
	}

	for i := 0; i < len(word)-1; i++ {
		variant := word[:i] + string(word[i+1]) + string(word[i]) + word[i+2:]
		variants = append(variants, variant)
	}

	return variants
}

func (p *DataMaskingPlugin) maskJSONDataWithRules(data interface{}, threshold float64, config Config, keywords map[string]string, regexRules map[string]*regexp.Regexp) (interface{}, []MaskingEvent) {
	var allEvents []MaskingEvent

	switch v := data.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{}, len(v))
		for key, value := range v {
			maskedValue, events := p.maskJSONDataWithRules(value, threshold, config, keywords, regexRules)
			result[key] = maskedValue
			allEvents = append(allEvents, events...)
		}
		return result, allEvents

	case []interface{}:
		result := make([]interface{}, len(v))
		for i, value := range v {
			maskedValue, events := p.maskJSONDataWithRules(value, threshold, config, keywords, regexRules)
			result[i] = maskedValue
			allEvents = append(allEvents, events...)
		}
		return result, allEvents

	case string:
		// If the string itself is JSON, mask within it structurally to avoid altering keys
		var inner interface{}
		if err := json.Unmarshal([]byte(v), &inner); err == nil {
			maskedInner, events := p.maskJSONDataWithRules(inner, threshold, config, keywords, regexRules)
			maskedJSON, mErr := json.Marshal(maskedInner)
			if mErr == nil {
				return string(maskedJSON), events
			}
		}
		maskedValue, events := p.maskPlainTextWithRules(v, threshold, config, keywords, regexRules)
		return maskedValue, events

	default:
		return v, nil
	}
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

func max2(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func buildEnabledMap(config Config) map[pii_entities.Entity]bool {
	enabled := make(map[pii_entities.Entity]bool)
	if config.ApplyAll {
		for entity := range pii_entities.Entities {
			enabled[entity] = true
		}
	} else {
		for _, ec := range config.PredefinedEntities {
			if ec.Enabled {
				enabled[pii_entities.Entity(ec.Entity)] = true
			}
		}
	}
	return enabled
}
