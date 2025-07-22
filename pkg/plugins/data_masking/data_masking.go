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

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

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
	Default        PredefinedEntity = "default"
	CreditCard     PredefinedEntity = "credit_card"
	CVV            PredefinedEntity = "cvv"
	Email          PredefinedEntity = "email"
	PhoneNumber    PredefinedEntity = "phone_number"
	SSN            PredefinedEntity = "ssn"
	IPAddress      PredefinedEntity = "ip_address"
	IPv6Address    PredefinedEntity = "ip6_address"
	BankAccount    PredefinedEntity = "bank_account"
	Password       PredefinedEntity = "password"
	APIKey         PredefinedEntity = "api_key"
	AccessToken    PredefinedEntity = "access_token"
	IBAN           PredefinedEntity = "iban"
	SwiftBIC       PredefinedEntity = "swift_bic"
	CryptoWallet   PredefinedEntity = "crypto_wallet"
	TaxID          PredefinedEntity = "tax_id"
	RoutingNumber  PredefinedEntity = "routing_number"
	UUID           PredefinedEntity = "uuid"
	JWTToken       PredefinedEntity = "jwt_token"
	MACAddress     PredefinedEntity = "mac_address"
	StripeKey      PredefinedEntity = "stripe_key"
	DriversLicense PredefinedEntity = "drivers_license"
	Passport       PredefinedEntity = "passport"
	Address        PredefinedEntity = "address"
	ZipCode        PredefinedEntity = "zip_code"
	SpanishDNI     PredefinedEntity = "spanish_dni"
	SpanishNIE     PredefinedEntity = "spanish_nie"
	SpanishCIF     PredefinedEntity = "spanish_cif"
	SpanishNSS     PredefinedEntity = "spanish_nss"
	SpanishIBAN    PredefinedEntity = "spanish_iban"
	SpanishPhone   PredefinedEntity = "spanish_phone"
	FrenchNIR      PredefinedEntity = "french_nir"     // French social security number
	ItalianCF      PredefinedEntity = "italian_cf"     // Italian fiscal code
	GermanID       PredefinedEntity = "german_id"      // German ID card number
	BrazilianCPF   PredefinedEntity = "brazilian_cpf"  // Brazilian individual taxpayer registry
	BrazilianCNPJ  PredefinedEntity = "brazilian_cnpj" // Brazilian company registry
	MexicanCURP    PredefinedEntity = "mexican_curp"   // Mexican personal ID
	MexicanRFC     PredefinedEntity = "mexican_rfc"    // Mexican tax ID
	USMedicareID   PredefinedEntity = "us_medicare"    // US Medicare ID
	ISIN           PredefinedEntity = "isin"           // International Securities Identification Number
	VehicleVIN     PredefinedEntity = "vehicle_vin"    // Vehicle identification number
	DeviceIMEI     PredefinedEntity = "device_imei"    // Mobile device IMEI
	DeviceMAC      PredefinedEntity = "device_mac"     // Device MAC address (alternative format)
	ArgentineDNI   PredefinedEntity = "argentine_dni"  // Argentine national ID
	ChileanRUT     PredefinedEntity = "chilean_rut"    // Chilean tax ID
	ColombianCC    PredefinedEntity = "colombian_cc"   // Colombian citizen ID
	PeruvianDNI    PredefinedEntity = "peruvian_dni"   // Peruvian national ID
	Date           PredefinedEntity = "date"
)

var predefinedEntityPatterns = map[PredefinedEntity]*regexp.Regexp{
	CreditCard:     regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`),
	CVV:            regexp.MustCompile(`(?i)cvv[\s-]*\d{3}`),
	Email:          regexp.MustCompile(`\b[A-Za-z0-9._%+-]+\s*@\s*[A-Za-z0-9.-]+\s*\.\s*[A-Za-z]{2,}\b`),
	SSN:            regexp.MustCompile(`\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b`),
	IPAddress:      regexp.MustCompile(`\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
	IPv6Address:    regexp.MustCompile(`\b(?:[a-fA-F0-9]{1,4}:){1,7}[a-fA-F0-9]{1,4}|\b(?:[a-fA-F0-9]{1,4}:){1,7}:\b`),
	BankAccount:    regexp.MustCompile(`\b\d{8,20}\b`),
	Password:       regexp.MustCompile(`(?i)password[\s]*[=:]\s*\S+`),
	APIKey:         regexp.MustCompile(`(?i)(api[_-]?key|access[_-]?key)[\s]*[=:]\s*\S+`),
	AccessToken:    regexp.MustCompile(`(?i)(access[_-]?token|bearer)[\s]*[=:]\s*\S+`),
	IBAN:           regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b`),
	SwiftBIC:       regexp.MustCompile(`\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b`),
	PhoneNumber:    regexp.MustCompile(`\b(\+?\d{1,4}[\s-]?)?(\(?\d{2,4}\)?[\s-]?)?\d{2,4}[\s-]?\d{2,4}[\s-]?\d{2,4}\b`),
	CryptoWallet:   regexp.MustCompile(`\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b|0x[a-fA-F0-9]{40}\b`),
	TaxID:          regexp.MustCompile(`\b\d{2}[-\s]?\d{7}\b`),
	RoutingNumber:  regexp.MustCompile(`\b\d{9}\b`),
	UUID:           regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`),
	JWTToken:       regexp.MustCompile(`\beyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\b`),
	MACAddress:     regexp.MustCompile(`\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b`),
	StripeKey:      regexp.MustCompile(`(?i)(sk|pk|rk|whsec)_(test|live)_[a-z0-9]{24}`),
	DriversLicense: regexp.MustCompile(`\b([A-Z]{1,2}[-\s]?\d{2,7}|\d{9}|\d{3}[-\s]?\d{3}[-\s]?\d{3})\b`),
	Passport:       regexp.MustCompile(`\b[A-Z]{1,2}[0-9]{6,9}\b`),
	Address:        regexp.MustCompile(`\b\d+\s+[A-Za-z\s]+,\s+[A-Za-z\s]+,\s+[A-Z]{2}\s+\d{5}\b`),
	ZipCode:        regexp.MustCompile(`\b\d{5}(-\d{4})?\b`),
	SpanishDNI:     regexp.MustCompile(`\b\d{8}[A-HJ-NP-TV-Z]\b`),
	SpanishNIE:     regexp.MustCompile(`\b[XYZ]\d{7}[A-HJ-NP-TV-Z]\b`),
	SpanishCIF:     regexp.MustCompile(`\b[A-HJNPQRSUVW]\d{7}[A-J0-9]\b`),
	SpanishNSS:     regexp.MustCompile(`\b\d{2}[- ]?\d{8}[- ]?\d{2}\b`),
	SpanishIBAN:    regexp.MustCompile(`\bES\d{2}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`),
	SpanishPhone:   regexp.MustCompile(`\b(?:\+34|0034)?[- ]?(?:6|7|8|9)\d{8}\b`),
	FrenchNIR:      regexp.MustCompile(`\b[1-2]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b`),
	ItalianCF:      regexp.MustCompile(`\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b`),
	GermanID:       regexp.MustCompile(`\b[A-Z]{2}[A-Z0-9]{7}[0-9]\b`),
	BrazilianCPF:   regexp.MustCompile(`\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b`),
	BrazilianCNPJ:  regexp.MustCompile(`\b\d{2}\.?\d{3}\.?\d{3}/?\.?\d{4}-?\d{2}\b`),
	MexicanCURP:    regexp.MustCompile(`\b[A-Z]{4}\d{6}[HM][A-Z]{5}[0-9A-Z]\d\b`),
	MexicanRFC:     regexp.MustCompile(`\b[A-Z]{3,4}\d{6}[A-Z0-9]{3}\b`),
	USMedicareID:   regexp.MustCompile(`\b[1-9]\d{2}-\d{2}-\d{4}[A-Z]\b`),
	ISIN:           regexp.MustCompile(`\b[A-Z]{2}[A-Z0-9]{9}\d\b`),
	VehicleVIN:     regexp.MustCompile(`\b[A-HJ-NPR-Z0-9]{17}\b`),
	DeviceIMEI:     regexp.MustCompile(`\b\d{15,17}\b`),
	DeviceMAC:      regexp.MustCompile(`\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b`),
	ArgentineDNI:   regexp.MustCompile(`\b\d{7,8}\b`),
	ChileanRUT:     regexp.MustCompile(`\b\d{1,2}\.?\d{3}\.?\d{3}-?[0-9K]\b`),
	ColombianCC:    regexp.MustCompile(`\b\d{8,10}\b`),
	PeruvianDNI:    regexp.MustCompile(`\b\d{8}\b`),
	Date:           regexp.MustCompile(`\b(\d{4}[-/]\d{2}[-/]\d{2}|\d{1,2}[-/]\d{1,2}[-/]\d{4}|\d{1,2}\s(?:de\s)?[a-zA-Z]+\s(?:de\s)?\d{4}|\d{1,2}(?:st|nd|rd|th)?\s[a-zA-Z]+\s\d{4}|[a-zA-Z]+\s\d{1,2}(?:st|nd|rd|th)?\s\d{4})\b`),
}

var predefinedEntityOrder = []PredefinedEntity{
	IBAN,
	PhoneNumber,
	CreditCard,
	CVV,
	Email,
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
	DriversLicense,
	Passport,
	Address,
	ZipCode,
	SpanishDNI,
	SpanishNIE,
	SpanishCIF,
	SpanishNSS,
	SpanishIBAN,
	SpanishPhone,
	FrenchNIR,
	ItalianCF,
	GermanID,
	BrazilianCPF,
	BrazilianCNPJ,
	MexicanCURP,
	MexicanRFC,
	USMedicareID,
	ISIN,
	VehicleVIN,
	DeviceIMEI,
	DeviceMAC,
	ArgentineDNI,
	ChileanRUT,
	ColombianCC,
	PeruvianDNI,
	Date,
}

// defaultEntityMasks defines default masking for pre-defined entities
var defaultEntityMasks = map[PredefinedEntity]string{
	Default:        "*****",
	CreditCard:     "[MASKED_CC]",
	CVV:            "[MASKED_CVV]",
	Email:          "[MASKED_EMAIL]",
	SSN:            "[MASKED_SSN]",
	IPAddress:      "[MASKED_IP]",
	IPv6Address:    "[MASKED_IP6]",
	BankAccount:    "[MASKED_ACCOUNT]",
	Password:       "[MASKED_PASSWORD]",
	APIKey:         "[MASKED_API_KEY]",
	AccessToken:    "[MASKED_TOKEN]",
	IBAN:           "[MASKED_IBAN]",
	PhoneNumber:    "[MASKED_PHONE]",
	SwiftBIC:       "[MASKED_BIC]",
	CryptoWallet:   "[MASKED_WALLET]",
	TaxID:          "[MASKED_TAX_ID]",
	RoutingNumber:  "[MASKED_ROUTING]",
	UUID:           "[MASKED_UUID]",
	JWTToken:       "[MASKED_JWT_TOKEN]",
	MACAddress:     "[MASKED_MAC]",
	StripeKey:      "[MASKED_API_KEY]",
	DriversLicense: "[MASKED_LICENSE]",
	Passport:       "[MASKED_PASSPORT]",
	Address:        "[MASKED_ADDRESS]",
	ZipCode:        "[MASKED_ZIP]",
	SpanishDNI:     "[MASKED_DNI]",
	SpanishNIE:     "[MASKED_NIE]",
	SpanishCIF:     "[MASKED_CIF]",
	SpanishNSS:     "[MASKED_NSS]",
	SpanishIBAN:    "[MASKED_ES_IBAN]",
	SpanishPhone:   "[MASKED_ES_PHONE]",
	FrenchNIR:      "[MASKED_FR_NIR]",
	ItalianCF:      "[MASKED_IT_CF]",
	GermanID:       "[MASKED_DE_ID]",
	BrazilianCPF:   "[MASKED_BR_CPF]",
	BrazilianCNPJ:  "[MASKED_BR_CNPJ]",
	MexicanCURP:    "[MASKED_MX_CURP]",
	MexicanRFC:     "[MASKED_MX_RFC]",
	USMedicareID:   "[MASKED_MEDICARE]",
	ISIN:           "[MASKED_ISIN]",
	VehicleVIN:     "[MASKED_VIN]",
	DeviceIMEI:     "[MASKED_IMEI]",
	DeviceMAC:      "[MASKED_MAC]",
	ArgentineDNI:   "[MASKED_AR_DNI]",
	ChileanRUT:     "[MASKED_CL_RUT]",
	ColombianCC:    "[MASKED_CO_CC]",
	PeruvianDNI:    "[MASKED_PE_DNI]",
	Date:           "[MASKED_DATE]",
}

// hashMapKey is the key used to store the hash map in the context
type hashMapKey struct{}

// hashToOriginalMap is a map from hash to original value
type hashToOriginalMap map[string]string

type DataMaskingPlugin struct {
	logger      *logrus.Logger
	memoryCache *common.TTLMap
	keywords    map[string]string         // map of keyword to mask value
	regexRules  map[string]*regexp.Regexp // map of regex pattern to mask value
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
	MaxEditDistance     int                     `mapstructure:"max_edit_distance"` // Maximum edit distance for fuzzy matching
	NormalizeInput      bool                    `mapstructure:"normalize_input"`   // Normalize input before matching
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

func NewDataMaskingPlugin(logger *logrus.Logger, c *cache.Cache) pluginiface.Plugin {
	return &DataMaskingPlugin{
		logger:      logger,
		memoryCache: c.GetTTLMap(cache.DataMaskingTTLName),
		keywords:    make(map[string]string),
		regexRules:  make(map[string]*regexp.Regexp),
	}
}

func (p *DataMaskingPlugin) Name() string {
	return PluginName
}

func (p *DataMaskingPlugin) RequiredPlugins() []string {
	var requiredPlugins []string
	return requiredPlugins
}

func (p *DataMaskingPlugin) Stages() []types.Stage {
	return []types.Stage{}
}

func (p *DataMaskingPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest, types.PostResponse}
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

	if cfg.ReversibleHashing.Enabled && cfg.ReversibleHashing.Secret == "" {
		return fmt.Errorf("reversible_hashing.secret must be set when reversible_hashing is enabled")
	}

	return nil
}

func (p *DataMaskingPlugin) Execute(
	ctx context.Context,
	cfg types.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	evtCtx *metrics.EventContext,
) (*types.PluginResponse, error) {
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

	if config.ReversibleHashing.Enabled {
		traceId, ok := ctx.Value(common.TraceIdKey).(string)
		if ok {
			if cfg.Stage == types.PreRequest {
				// Initialize an empty hash map for this trace ID
				p.memoryCache.Set(traceId, make(hashToOriginalMap))
			}
		}
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
			// Try to compile the regex
			regex, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return nil, fmt.Errorf("failed to compile regex pattern '%s': %v", rule.Pattern, err)
			}

			// Store both the pattern string and the compiled regex
			p.regexRules[rule.Pattern] = regex
			p.keywords[rule.Pattern] = maskValue
		}
	}

	var allEvents []MaskingEvent
	hashMap := make(hashToOriginalMap)
	secret := config.ReversibleHashing.Secret

	// Check if reversible hashing is enabled
	if config.ReversibleHashing.Enabled && cfg.Stage == types.PostResponse {
		traceId, ok := ctx.Value(common.TraceIdKey).(string)
		if ok {
			// Get the hash map from the memory cache
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

			// If this is a response in postresponse stage and reversible hashing is enabled, skip masking and just restore original values
			if !isRequest && cfg.Stage == types.PostResponse && config.ReversibleHashing.Enabled {
				maskedData = restoreFromHashes(jsonData, hashMap)
			} else {
				// Otherwise, mask the data as usual
				maskedData, events = p.maskJSONData(jsonData, config.SimilarityThreshold, config)

				// If reversible hashing is enabled and this is a request in prerequest stage, replace masked values with hashes
				if config.ReversibleHashing.Enabled && isRequest && cfg.Stage == types.PreRequest {
					for i := range events {
						hash := generateReversibleHash(secret, events[i].OriginalValue)
						events[i].ReversibleKey = hash
						hashMap[hash] = events[i].OriginalValue
					}

					// Replace masked values with hashes in the JSON data
					maskedData = replaceWithHashes(maskedData, events)

					// Store the updated hash map in the memory cache
					traceId, ok := ctx.Value(common.TraceIdKey).(string)
					if ok {
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

		// If this is a response in postresponse stage and reversible hashing is enabled, skip masking and just restore original values
		if !isRequest && cfg.Stage == types.PostResponse && config.ReversibleHashing.Enabled {
			maskedContent = content
			for hash, original := range hashMap {
				maskedContent = strings.ReplaceAll(maskedContent, hash, original)
			}
		} else {
			// Otherwise, mask the data as usual
			maskedContent, events = p.maskPlainText(content, config.SimilarityThreshold, config)

			// If reversible hashing is enabled and this is a request in prerequest stage, replace masked values with hashes
			if config.ReversibleHashing.Enabled && isRequest && cfg.Stage == types.PreRequest {
				for i := range events {
					hash := generateReversibleHash(secret, events[i].OriginalValue)
					events[i].ReversibleKey = hash
					hashMap[hash] = events[i].OriginalValue

					// Replace masked value with hash in the content
					maskedContent = strings.ReplaceAll(maskedContent, events[i].MaskedWith, hash)
				}

				// Store the updated hash map in the memory cache
				traceId, ok := ctx.Value(common.TraceIdKey).(string)
				if ok {
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

	return &types.PluginResponse{
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
		// Replace masked values with hashes
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

// restoreFromHashes restores original values from hashes in JSON data
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
		// Restore original values from hashes
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

// calculateSimilarity returns a similarity score between 0 and 1
func calculateSimilarity(s1, s2 string) float64 {
	distance := levenshteinDistance(s1, s2)
	maxLen := float64(max(len(s1), len(s2)))
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - float64(distance)/maxLen
}

func (p *DataMaskingPlugin) findSimilarKeyword(text string, threshold float64) (string, string, bool) {
	// First check for exact matches
	for keyword, maskWith := range p.keywords {
		// Skip regex patterns
		if _, exists := p.regexRules[keyword]; exists {
			continue
		}

		if strings.Contains(text, keyword) {
			return text, maskWith, true
		}
	}

	// Then check for fuzzy matches
	for keyword, maskWith := range p.keywords {
		// Skip regex patterns
		if _, exists := p.regexRules[keyword]; exists {
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
	// Convert to lowercase
	text = strings.ToLower(text)

	// Remove common separators
	text = strings.ReplaceAll(text, "-", "")
	text = strings.ReplaceAll(text, " ", "")
	text = strings.ReplaceAll(text, ".", "")
	text = strings.ReplaceAll(text, "/", "")

	return text
}

func (p *DataMaskingPlugin) maskPlainText(content string, threshold float64, config Config) (string, []MaskingEvent) {
	var events []MaskingEvent
	maskedContent := content
	// First apply predefined entity patterns
	for _, entityType := range predefinedEntityOrder {
		pattern, exists := predefinedEntityPatterns[entityType]
		if !exists {
			continue
		}

		// Check if this entity is enabled in the configuration
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
		maskValue := defaultEntityMasks[entityType]
		if config.ApplyAll {
			maskValue = defaultEntityMasks[Default]
		}
		// Standard regex matching
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

	// Then apply custom regex patterns
	for pattern, regex := range p.regexRules {
		// Skip predefined entity patterns which are already processed
		isPredefined := false
		for _, entityType := range predefinedEntityOrder {
			if entityPattern, exists := predefinedEntityPatterns[entityType]; exists {
				if entityPattern.String() == pattern {
					isPredefined = true
					break
				}
			}
		}

		if isPredefined {
			continue
		}

		// Apply custom regex pattern
		matches := regex.FindAllString(maskedContent, -1)
		if len(matches) > 0 {
			maskValue := p.keywords[pattern]
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

	// Apply keyword matching (exact, not fuzzy)
	for keyword, maskValue := range p.keywords {
		// Skip regex patterns which are already processed
		if _, exists := p.regexRules[keyword]; exists {
			continue
		}

		// Apply exact keyword matching
		if strings.Contains(maskedContent, keyword) {
			events = append(events, MaskingEvent{
				Entity:        keyword,
				OriginalValue: maskedContent,
				MaskedWith:    maskValue,
			})
			maskedContent = strings.ReplaceAll(maskedContent, keyword, maskValue)
		}
	}

	// Apply keyword fuzzy matching
	words := strings.Fields(maskedContent)
	modified := false
	for i, word := range words {
		if origWord, maskWith, found := p.findSimilarKeyword(word, threshold); found {
			words[i] = p.maskContent(origWord, maskWith, true)
			modified = true
		}
	}

	if modified {
		maskedContent = strings.Join(words, " ")
	}

	return maskedContent, events
}

// Add a function to generate variants of a string with edit distance <= maxDistance
func (p *DataMaskingPlugin) generateVariants(word string, maxDistance int) []string {
	if maxDistance <= 0 || len(word) <= 3 {
		return []string{word}
	}

	variants := []string{word}

	// Generate variants with one character deleted
	for i := 0; i < len(word); i++ {
		variant := word[:i] + word[i+1:]
		variants = append(variants, variant)
	}

	// Generate variants with one character substituted
	for i := 0; i < len(word); i++ {
		// Common substitutions
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

	// Generate variants with one character transposed
	for i := 0; i < len(word)-1; i++ {
		variant := word[:i] + string(word[i+1]) + string(word[i]) + word[i+2:]
		variants = append(variants, variant)
	}

	return variants
}

// Update the maskJSONData function to use the enhanced configuration
func (p *DataMaskingPlugin) maskJSONData(data interface{}, threshold float64, config Config) (interface{}, []MaskingEvent) {
	var allEvents []MaskingEvent

	switch v := data.(type) {
	case map[string]interface{}:
		// Process each key-value pair in the map
		result := make(map[string]interface{}, len(v))
		for key, value := range v {
			maskedValue, events := p.maskJSONData(value, threshold, config)
			result[key] = maskedValue
			allEvents = append(allEvents, events...)
		}
		return result, allEvents

	case []interface{}:
		// Process each item in the array
		result := make([]interface{}, len(v))
		for i, value := range v {
			maskedValue, events := p.maskJSONData(value, threshold, config)
			result[i] = maskedValue
			allEvents = append(allEvents, events...)
		}
		return result, allEvents

	case string:
		// Process the string value
		maskedValue, events := p.maskPlainText(v, threshold, config)
		return maskedValue, events

	default:
		// Return other types (int, bool, etc.) as-is
		return v, nil
	}
}
