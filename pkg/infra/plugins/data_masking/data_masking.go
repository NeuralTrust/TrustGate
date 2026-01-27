package data_masking

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/pluginiface"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/pii_entities"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/types"
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
	Secret  string `mapstructure:"secret"`
}

type Config struct {
	ReversibleHashing   ReversibleHashingConfig `mapstructure:"reversible_hashing"`
	Rules               []Rule                  `mapstructure:"rules"`
	SimilarityThreshold float64                 `mapstructure:"similarity_threshold"`
	PredefinedEntities  []EntityConfig          `mapstructure:"predefined_entities"`
	ApplyAll            bool                    `mapstructure:"apply_all"`
	MaxEditDistance     int                     `mapstructure:"max_edit_distance"`
	NormalizeInput      bool                    `mapstructure:"normalize_input"`
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

	if config.ReversibleHashing.Enabled {
		traceId, ok := ctx.Value(common.TraceIdKey).(string)
		if ok && cfg.Stage == pluginTypes.PreRequest {
			if p.memoryCache != nil {
				p.memoryCache.Set(traceId, make(hashToOriginalMap))
			}
		}
	}

	// Build per-execution rule maps to avoid shared mutable state across goroutines
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
				return nil, fmt.Errorf("failed to compile regex pattern '%s': %v", rule.Pattern, err)
			}
			regexRules[rule.Pattern] = regex
			keywords[rule.Pattern] = maskValue
		}
	}

	var allEvents []MaskingEvent
	hashMap := make(hashToOriginalMap)
	secret := config.ReversibleHashing.Secret

	if config.ReversibleHashing.Enabled && cfg.Stage == pluginTypes.PostResponse {
		traceId, ok := ctx.Value(common.TraceIdKey).(string)
		if ok && p.memoryCache != nil {
			if value, exists := p.memoryCache.Get(traceId); exists {
				if hm, ok := value.(hashToOriginalMap); ok {
					hashMap = hm
				}
			}
		}
	}

	processBody := func(body []byte, isRequest bool) ([]byte, error) {
		var jsonData interface{}
		if err := json.Unmarshal(body, &jsonData); err == nil {
			var maskedData interface{}
			var events []MaskingEvent

			if !isRequest && cfg.Stage == pluginTypes.PostResponse && config.ReversibleHashing.Enabled {
				maskedData = restoreFromHashes(jsonData, hashMap)
			} else {
				maskedData, events = p.maskJSONDataWithRules(jsonData, config.SimilarityThreshold, config, keywords, regexRules)

				if config.ReversibleHashing.Enabled && isRequest && cfg.Stage == pluginTypes.PreRequest {
					for i := range events {
						hash := generateReversibleHash(secret, events[i].OriginalValue)
						events[i].ReversibleKey = hash
						hashMap[hash] = events[i].OriginalValue
					}

					maskedData = replaceWithHashes(maskedData, events)

					traceId, ok := ctx.Value(common.TraceIdKey).(string)
					if ok && p.memoryCache != nil {
						p.memoryCache.Set(traceId, hashMap)
					}
				}
			}

			maskedJSON, err := json.Marshal(maskedData)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal masked JSON: %v", err)
			}
			allEvents = append(allEvents, events...)
			return maskedJSON, nil
		}

		content := string(body)
		var maskedContent string
		var events []MaskingEvent

		if !isRequest && cfg.Stage == pluginTypes.PostResponse && config.ReversibleHashing.Enabled {
			maskedContent = content
			for hash, original := range hashMap {
				maskedContent = strings.ReplaceAll(maskedContent, hash, original)
			}
		} else {
			maskedContent, events = p.maskPlainTextWithRules(content, config.SimilarityThreshold, config, keywords, regexRules)

			if config.ReversibleHashing.Enabled && isRequest && cfg.Stage == pluginTypes.PreRequest {
				for i := range events {
					hash := generateReversibleHash(secret, events[i].OriginalValue)
					events[i].ReversibleKey = hash
					hashMap[hash] = events[i].OriginalValue
					maskedContent = strings.ReplaceAll(maskedContent, events[i].MaskedWith, hash)
				}

				traceId, ok := ctx.Value(common.TraceIdKey).(string)
				if ok && p.memoryCache != nil {
					p.memoryCache.Set(traceId, hashMap)
				}
			}
		}

		allEvents = append(allEvents, events...)
		return []byte(maskedContent), nil
	}

	if req != nil && len(req.Body) > 0 {
		maskedBody, err := processBody(req.Body, true)
		if err != nil {
			return nil, err
		}
		req.Body = maskedBody
	}

	if resp != nil && len(resp.Body) > 0 {
		maskedBody, err := processBody(resp.Body, false)
		if err != nil {
			return nil, err
		}
		resp.Body = maskedBody
	}

	evtCtx.SetExtras(DataMaskingData{
		Masked: len(allEvents) > 0,
		Events: allEvents,
	})

	return &pluginTypes.PluginResponse{
		StatusCode: 200,
		Message:    "Content masked successfully",
	}, nil
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

	// Guard against potential allocation overflow (l2+1 sizing below)
	maxInt := int(^uint(0) >> 1)
	if l2 >= maxInt-1 {
		return maxInt
	}

	// Use O(min(l1,l2)) space dynamic programming to minimize allocations
	if l1 < l2 {
		// Ensure s1 is the longer string
		s1, s2 = s2, s1
		l1, l2 = l2, l1
	}

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

	for _, entityType := range pii_entities.DetectionOrder {
		pattern, exists := pii_entities.Patterns[entityType]
		if !exists {
			continue
		}

		entityEnabled := false
		for _, entity := range config.PredefinedEntities {
			if entity.Entity == string(entityType) && entity.Enabled {
				entityEnabled = true
				break
			}
		}
		if !entityEnabled && !config.ApplyAll {
			continue
		}

		maskValue := pii_entities.DefaultMasks[entityType]
		if config.ApplyAll {
			maskValue = pii_entities.DefaultMasks[pii_entities.Default]
		}

		matches := pattern.FindAllString(maskedContent, -1)
		if len(matches) > 0 {
			for _, match := range matches {
				events = append(events, MaskingEvent{
					Entity:        string(entityType),
					OriginalValue: match,
					MaskedWith:    maskValue,
				})
				maskedContent = strings.ReplaceAll(maskedContent, match, maskValue)
			}
		}
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
