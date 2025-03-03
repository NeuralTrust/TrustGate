package data_masking

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

const (
	PluginName          = "data_masking"
	DefaultMaskChar     = "*"
	SimilarityThreshold = 0.8
)

// PredefinedEntity represents a pre-defined entity type to mask
type PredefinedEntity string

const (
	CreditCard    PredefinedEntity = "credit_card"
	Email         PredefinedEntity = "email"
	PhoneNumber   PredefinedEntity = "phone_number"
	SSN           PredefinedEntity = "ssn"
	IPAddress     PredefinedEntity = "ip_address"
	BankAccount   PredefinedEntity = "bank_account"
	Password      PredefinedEntity = "password"
	APIKey        PredefinedEntity = "api_key"
	AccessToken   PredefinedEntity = "access_token"
	IBAN          PredefinedEntity = "iban"
	SwiftBIC      PredefinedEntity = "swift_bic"
	CryptoWallet  PredefinedEntity = "crypto_wallet"
	TaxID         PredefinedEntity = "tax_id"
	RoutingNumber PredefinedEntity = "routing_number"
)

// predefinedEntityPatterns maps entity types to their regex patterns
var predefinedEntityPatterns = map[PredefinedEntity]string{
	CreditCard:    `\b(?:\d[ -]*?){13,19}\b`,
	Email:         `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`,
	PhoneNumber:   `\+?(\d{1,4}[-\s]?)?(\d{3}[-\s]?\d{3}[-\s]?\d{4})`,
	SSN:           `\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b`,
	IPAddress:     `\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`,
	BankAccount:   `\b\d{8,20}\b`,
	Password:      `(?i)password[\s]*[=:]\s*\S+`,
	APIKey:        `(?i)(api[_-]?key|access[_-]?key)[\s]*[=:]\s*\S+`,
	AccessToken:   `(?i)(access[_-]?token|bearer)[\s]*[=:]\s*\S+`,
	IBAN:          `\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b`,
	SwiftBIC:      `\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b`,
	CryptoWallet:  `\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b|0x[a-fA-F0-9]{40}\b`,
	TaxID:         `\b\d{2}[-\s]?\d{7}\b`,
	RoutingNumber: `\b\d{9}\b`,
}

var predefinedEntityOrder = []PredefinedEntity{
	CreditCard,
	Email,
	IBAN,
	PhoneNumber,
	SSN,
	IPAddress,
	BankAccount,
	Password,
	APIKey,
	AccessToken,
	SwiftBIC,
	CryptoWallet,
	TaxID,
	RoutingNumber,
}

// defaultEntityMasks defines default masking for pre-defined entities
var defaultEntityMasks = map[PredefinedEntity]string{
	CreditCard:    "[MASKED_CC]",
	Email:         "[MASKED_EMAIL]",
	PhoneNumber:   "[MASKED_PHONE]",
	SSN:           "[MASKED_SSN]",
	IPAddress:     "[MASKED_IP]",
	BankAccount:   "[MASKED_ACCOUNT]",
	Password:      "[MASKED_PASSWORD]",
	APIKey:        "[MASKED_API_KEY]",
	AccessToken:   "[MASKED_TOKEN]",
	IBAN:          "[MASKED_IBAN]",
	SwiftBIC:      "[MASKED_BIC]",
	CryptoWallet:  "[MASKED_WALLET]",
	TaxID:         "[MASKED_TAX_ID]",
	RoutingNumber: "[MASKED_ROUTING]",
}

type DataMaskingPlugin struct {
	logger     *logrus.Logger
	keywords   map[string]string         // map of keyword to mask value
	regexRules map[string]*regexp.Regexp // map of regex pattern to mask value
}

type Config struct {
	Rules               []Rule         `mapstructure:"rules"`
	SimilarityThreshold float64        `mapstructure:"similarity_threshold"`
	PredefinedEntities  []EntityConfig `mapstructure:"predefined_entities"`
}

type EntityConfig struct {
	Entity      string `mapstructure:"entity"`       // Pre-defined entity type
	Enabled     bool   `mapstructure:"enabled"`      // Whether to enable this entity
	MaskWith    string `mapstructure:"mask_with"`    // Optional custom mask
	PreserveLen bool   `mapstructure:"preserve_len"` // Whether to preserve length
}

type Rule struct {
	Pattern     string `mapstructure:"pattern"`      // Keyword or regex pattern
	Type        string `mapstructure:"type"`         // "keyword" or "regex"
	MaskWith    string `mapstructure:"mask_with"`    // Character or string to mask with
	PreserveLen bool   `mapstructure:"preserve_len"` // Whether to preserve the length of masked content
}

// levenshteinDistance calculates the minimum number of single-character edits required to change one word into another
func levenshteinDistance(s1, s2 string) int {
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

// min returns the minimum of three integers
func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// calculateSimilarity returns a similarity score between 0 and 1
func calculateSimilarity(s1, s2 string) float64 {
	distance := levenshteinDistance(s1, s2)
	maxLen := float64(max(len(s1), len(s2)))
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - float64(distance)/maxLen
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (p *DataMaskingPlugin) findSimilarKeyword(text string, threshold float64) (string, string, string, bool) {
	words := strings.Fields(text)
	for _, word := range words {
		for keyword, maskWith := range p.keywords {
			similarity := calculateSimilarity(word, keyword)
			if similarity >= threshold {
				return word, keyword, maskWith, true
			}
		}
	}
	return "", "", "", false
}

func NewDataMaskingPlugin(logger *logrus.Logger) pluginiface.Plugin {
	return &DataMaskingPlugin{
		logger:     logger,
		keywords:   make(map[string]string),
		regexRules: make(map[string]*regexp.Regexp),
	}
}

func (p *DataMaskingPlugin) Name() string {
	return PluginName
}

func (p *DataMaskingPlugin) Stages() []types.Stage {
	return []types.Stage{types.PreRequest, types.PreResponse}
}

func (p *DataMaskingPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest, types.PreResponse}
}

func (p *DataMaskingPlugin) ValidateConfig(config types.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %v", err)
	}

	if len(cfg.Rules) == 0 && len(cfg.PredefinedEntities) == 0 {
		return fmt.Errorf("at least one rule or predefined entity must be specified")
	}

	// Validate custom rules
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

	// Validate predefined entities
	for _, entity := range cfg.PredefinedEntities {
		if _, exists := predefinedEntityPatterns[PredefinedEntity(entity.Entity)]; !exists {
			return fmt.Errorf("invalid predefined entity type: %s", entity.Entity)
		}
	}

	return nil
}

func (p *DataMaskingPlugin) maskContent(content string, pattern string, maskWith string, preserveLen bool) string {
	if preserveLen {
		if len(maskWith) > 1 {
			return strings.Repeat(maskWith, 1)
		}
		return strings.Repeat("*", len(content))
	}
	return maskWith
}

func (p *DataMaskingPlugin) Execute(
	ctx context.Context,
	cfg types.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
) (*types.PluginResponse, error) {
	var config Config
	if err := mapstructure.Decode(cfg.Settings, &config); err != nil {
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}

	threshold := config.SimilarityThreshold
	if threshold == 0 {
		threshold = SimilarityThreshold
	}

	// Initialize rules
	p.keywords = make(map[string]string)
	p.regexRules = make(map[string]*regexp.Regexp)

	// Add predefined entity rules
	for _, entity := range config.PredefinedEntities {
		if !entity.Enabled {
			continue
		}

		entityType := PredefinedEntity(entity.Entity)
		pattern, exists := predefinedEntityPatterns[entityType]
		if !exists {
			continue
		}

		maskValue := entity.MaskWith
		if maskValue == "" {
			maskValue = defaultEntityMasks[entityType]
		}

		regex, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile predefined pattern for entity %s: %v", entity.Entity, err)
		}
		p.regexRules[pattern] = regex
		p.keywords[pattern] = maskValue
	}

	// Add custom rules
	for _, rule := range config.Rules {
		maskValue := rule.MaskWith
		if maskValue == "" {
			maskValue = DefaultMaskChar
		}

		if rule.Type == "keyword" {
			p.keywords[rule.Pattern] = maskValue
		} else if rule.Type == "regex" {
			regex, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return nil, fmt.Errorf("failed to compile regex pattern '%s': %v", rule.Pattern, err)
			}
			p.regexRules[rule.Pattern] = regex
			p.keywords[rule.Pattern] = maskValue
		}
	}

	// Process request body if in PreRequest stage
	if req != nil && len(req.Body) > 0 {
		var jsonData interface{}
		if err := json.Unmarshal(req.Body, &jsonData); err == nil {
			// If it's valid JSON, process it as JSON
			maskedData := p.maskJSONData(jsonData, threshold)
			maskedJSON, err := json.Marshal(maskedData)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal masked JSON: %v", err)
			}
			req.Body = maskedJSON
		} else {
			// If it's not JSON, process it as plain text
			content := string(req.Body)
			maskedContent := p.maskPlainText(content, threshold)
			req.Body = []byte(maskedContent)
		}
	}

	if resp != nil && len(resp.Body) > 0 {
		var jsonData interface{}
		if err := json.Unmarshal(resp.Body, &jsonData); err == nil {
			maskedData := p.maskJSONData(jsonData, threshold)
			maskedJSON, err := json.Marshal(maskedData)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal masked JSON: %v", err)
			}
			resp.Body = maskedJSON
		} else {
			content := string(resp.Body)
			maskedContent := p.maskPlainText(content, threshold)
			resp.Body = []byte(maskedContent)
		}
	}

	return &types.PluginResponse{
		StatusCode: 200,
		Message:    "Content masked successfully",
	}, nil
}

// maskPlainText processes plain text content and applies masking rules
func (p *DataMaskingPlugin) maskPlainText(content string, threshold float64) string {
	maskedContent := content

	// Apply regex masking using the ordered entity list
	for _, entityType := range predefinedEntityOrder {
		_, exists := predefinedEntityPatterns[entityType]
		if !exists {
			continue
		}
		regex := p.regexRules[string(entityType)]
		if regex == nil {
			continue
		}

		matches := regex.FindAllString(maskedContent, -1)
		if len(matches) > 0 {
			for _, match := range matches {
				maskedContent = strings.ReplaceAll(maskedContent, match, defaultEntityMasks[entityType])
			}
			return maskedContent // Return immediately after first match is masked
		}
	}

	words := strings.Fields(maskedContent)
	modified := false
	for i, word := range words {
		if origWord, keyword, maskWith, found := p.findSimilarKeyword(word, threshold); found {
			words[i] = p.maskContent(origWord, keyword, maskWith, true)
			modified = true
		}
	}

	if modified {
		maskedContent = strings.Join(words, " ")
	}

	return maskedContent
}

// maskJSONData recursively processes JSON data and masks sensitive information
func (p *DataMaskingPlugin) maskJSONData(data interface{}, threshold float64) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, value := range v {
			switch val := value.(type) {
			case string:
				maskedValue := val
				// Split the string into words for fuzzy matching
				words := strings.Fields(val)
				needsMasking := false

				// Check for fuzzy matches first
				for i, word := range words {
					for keyword, maskWith := range p.keywords {
						if _, isRegex := p.regexRules[keyword]; !isRegex {
							similarity := calculateSimilarity(word, keyword)
							if similarity >= threshold {
								words[i] = maskWith
								needsMasking = true
								break
							}
						}
					}
				}

				if needsMasking {
					maskedValue = strings.Join(words, " ")
				}

				// Check for predefined entities if no fuzzy match was found
				if maskedValue == val {
					for pattern, regex := range p.regexRules {
						if regex.MatchString(val) {
							// Find the corresponding entity type
							for entityType, entityPattern := range predefinedEntityPatterns {
								if pattern == entityPattern {
									maskedValue = defaultEntityMasks[entityType]
									break
								}
							}
						}
					}
				}

				// Check for sensitive keywords in the key name
				if maskedValue == val && (strings.Contains(strings.ToLower(key), "secret") || strings.Contains(strings.ToLower(key), "key")) {
					maskedValue = "[MASKED_KEY]"
				}
				result[key] = maskedValue
			default:
				result[key] = p.maskJSONData(value, threshold)
			}
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, value := range v {
			result[i] = p.maskJSONData(value, threshold)
		}
		return result
	case string:
		return p.maskPlainText(v, threshold)
	default:
		return v
	}
}
