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
	IPv6Address   PredefinedEntity = "ip6_address"
	BankAccount   PredefinedEntity = "bank_account"
	Password      PredefinedEntity = "password"
	APIKey        PredefinedEntity = "api_key"
	AccessToken   PredefinedEntity = "access_token"
	IBAN          PredefinedEntity = "iban"
	SwiftBIC      PredefinedEntity = "swift_bic"
	CryptoWallet  PredefinedEntity = "crypto_wallet"
	TaxID         PredefinedEntity = "tax_id"
	RoutingNumber PredefinedEntity = "routing_number"
	UUID          PredefinedEntity = "uuid"
	JWTToken      PredefinedEntity = "jwt_token"
	MACAddress    PredefinedEntity = "mac_address"
	StripeKey     PredefinedEntity = "stripe_key"
)

var predefinedEntityPatterns = map[PredefinedEntity]*regexp.Regexp{
	CreditCard:    regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`),
	Email:         regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`),
	SSN:           regexp.MustCompile(`\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b`),
	IPAddress:     regexp.MustCompile(`\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
	IPv6Address:   regexp.MustCompile(`\b([a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b`),
	BankAccount:   regexp.MustCompile(`\b\d{8,20}\b`),
	Password:      regexp.MustCompile(`(?i)password[\s]*[=:]\s*\S+`),
	APIKey:        regexp.MustCompile(`(?i)(api[_-]?key|access[_-]?key)[\s]*[=:]\s*\S+`),
	AccessToken:   regexp.MustCompile(`(?i)(access[_-]?token|bearer)[\s]*[=:]\s*\S+`),
	IBAN:          regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b`),
	PhoneNumber:   regexp.MustCompile(`\b\+?(\d{1,4}[-\s]?)?(\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{4})\b`),
	SwiftBIC:      regexp.MustCompile(`\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b`),
	CryptoWallet:  regexp.MustCompile(`\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b|0x[a-fA-F0-9]{40}\b`),
	TaxID:         regexp.MustCompile(`\b\d{2}[-\s]?\d{7}\b`),
	RoutingNumber: regexp.MustCompile(`\b\d{9}\b`),
	UUID:          regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`),
	JWTToken:      regexp.MustCompile(`\beyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\b`),
	MACAddress:    regexp.MustCompile(`\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b`),
	StripeKey:     regexp.MustCompile(`(?i)(sk|pk|rk|whsec)_(test|live)_[a-z0-9]{24}`),
}

var predefinedEntityOrder = []PredefinedEntity{
	CreditCard,
	Email,
	IBAN,
	PhoneNumber,
	SSN,
	IPAddress,
	IPv6Address,
	BankAccount,
	Password,
	APIKey,
	AccessToken,
	SwiftBIC,
	CryptoWallet,
	TaxID,
	RoutingNumber,
	UUID,
	JWTToken,
	MACAddress,
	StripeKey,
}

// defaultEntityMasks defines default masking for pre-defined entities
var defaultEntityMasks = map[PredefinedEntity]string{
	CreditCard:    "[MASKED_CC]",
	Email:         "[MASKED_EMAIL]",
	SSN:           "[MASKED_SSN]",
	IPAddress:     "[MASKED_IP]",
	IPv6Address:   "[MASKED_IP6]",
	BankAccount:   "[MASKED_ACCOUNT]",
	Password:      "[MASKED_PASSWORD]",
	APIKey:        "[MASKED_API_KEY]",
	AccessToken:   "[MASKED_TOKEN]",
	IBAN:          "[MASKED_IBAN]",
	PhoneNumber:   "[MASKED_PHONE]",
	SwiftBIC:      "[MASKED_BIC]",
	CryptoWallet:  "[MASKED_WALLET]",
	TaxID:         "[MASKED_TAX_ID]",
	RoutingNumber: "[MASKED_ROUTING]",
	UUID:          "[MASKED_UUID]",
	JWTToken:      "[MASKED_JWT_TOKEN]",
	MACAddress:    "[MASKED_MAC]",
	StripeKey:     "[MASKED_API_KEY]",
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
	ApplyAll            bool           `mapstructure:"apply_all"`
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
	return []types.Stage{}
}

func (p *DataMaskingPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest, types.PreResponse}
}

func (p *DataMaskingPlugin) ValidateConfig(config types.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %v", err)
	}

	if len(cfg.Rules) == 0 && len(cfg.PredefinedEntities) == 0 && !cfg.ApplyAll {
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

	if !cfg.ApplyAll && len(cfg.PredefinedEntities) > 0 {
		for _, entity := range cfg.PredefinedEntities {
			if _, exists := predefinedEntityPatterns[PredefinedEntity(entity.Entity)]; !exists {
				return fmt.Errorf("invalid predefined entity type: %s", entity.Entity)
			}
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

	if config.ApplyAll {
		for entityType, pattern := range predefinedEntityPatterns {
			maskValue, exists := defaultEntityMasks[entityType]
			if !exists {
				maskValue = "[MASKED]"
			}

			p.regexRules[pattern.String()] = pattern
			p.keywords[pattern.String()] = maskValue
		}
	} else {
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

			p.regexRules[pattern.String()] = pattern
			p.keywords[pattern.String()] = maskValue
		}
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
			// If it's valid JSON, process it as JSON
			maskedData := p.maskJSONData(jsonData, threshold)
			maskedJSON, err := json.Marshal(maskedData)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal masked JSON: %v", err)
			}
			resp.Body = maskedJSON
		} else {
			// If it's not JSON, process it as plain text
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
						} else {
							if p.regexRules[keyword].MatchString(word) {
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
