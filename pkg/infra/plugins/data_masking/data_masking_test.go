package data_masking

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	cacheMocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/pii_entities"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// helpers to build rules for new per-execution maps
func buildAllRegexAndKeywords() (map[string]*regexp.Regexp, map[string]string) {
	rr := make(map[string]*regexp.Regexp, len(pii_entities.Patterns))
	kw := make(map[string]string, len(pii_entities.Patterns))
	for entity, pattern := range pii_entities.Patterns {
		rr[pattern.String()] = pattern
		if mask, ok := pii_entities.DefaultMasks[entity]; ok {
			kw[pattern.String()] = mask
		}
	}
	return rr, kw
}

func buildRegexAndKeywordsForEntities(entities []pii_entities.Entity) (map[string]*regexp.Regexp, map[string]string) {
	rr := make(map[string]*regexp.Regexp)
	kw := make(map[string]string)
	for _, entity := range entities {
		if pattern, ok := pii_entities.Patterns[entity]; ok {
			rr[pattern.String()] = pattern
			if mask, ok2 := pii_entities.DefaultMasks[entity]; ok2 {
				kw[pattern.String()] = mask
			}
		}
	}
	return rr, kw
}

func TestLevenshteinDistance(t *testing.T) {
	tests := []struct {
		input1 string
		input2 string
		expect int
	}{
		{"kitten", "sitting", 3},
		{"flaw", "lawn", 2},
		{"gumbo", "gambol", 2},
		{"test", "test", 0},
		{"", "hello", 5},
	}

	for _, tt := range tests {
		result := levenshteinDistance(tt.input1, tt.input2)
		assert.Equal(t, tt.expect, result, "Levenshtein distance mismatch")
	}
}

func TestCalculateSimilarity(t *testing.T) {
	assert.InDelta(t, 1.0, calculateSimilarity("test", "test"), 0.001)
	assert.InDelta(t, 0.75, calculateSimilarity("test", "tent"), 0.001)
	assert.InDelta(t, 0.2, calculateSimilarity("hello", "world"), 0.001)
}

func TestNormalizeText(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"123-456-7890", "1234567890"},
		{"test@example.com", "test@examplecom"},
		{"192.168.1.1", "19216811"},
		{"Hello World", "helloworld"},
	}

	for _, tt := range tests {
		result := normalizeText(tt.input)
		assert.Equal(t, tt.expect, result, "Text normalization mismatch")
	}
}

func TestGenerateVariants(t *testing.T) {
	plugin := &DataMaskingPlugin{}

	// Test with maxDistance = 0
	variants := plugin.generateVariants("test", 0)
	assert.Equal(t, 1, len(variants))
	assert.Equal(t, "test", variants[0])

	// Test with short word
	variants = plugin.generateVariants("hi", 1)
	assert.Equal(t, 1, len(variants))

	// Test with normal word and maxDistance = 1
	variants = plugin.generateVariants("test", 1)
	assert.Contains(t, variants, "test") // Original word
	assert.Contains(t, variants, "est")  // Deletion
	assert.Contains(t, variants, "tst")  // Deletion
	assert.Contains(t, variants, "tes")  // Deletion
	assert.Contains(t, variants, "tet")  // Deletion

	// Test with substitution
	variants = plugin.generateVariants("1234", 1)
	assert.Contains(t, variants, "1234") // Original
	assert.Contains(t, variants, "l234") // Substitution 1->l

	// Test with transposition
	variants = plugin.generateVariants("test", 1)
	assert.Contains(t, variants, "tset") // Transposition e<->s
}

func createTestConfig(entities []EntityConfig, applyAll bool) Config {
	return Config{
		ReversibleHashing: ReversibleHashingConfig{
			Enabled: false,
			Secret:  "",
		},
		SimilarityThreshold: 0.8,
		MaxEditDistance:     1,
		NormalizeInput:      true,
		ApplyAll:            applyAll,
		PredefinedEntities:  entities,
	}
}

func TestMasking_PhoneNumber(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	regexRules, keywords := buildRegexAndKeywordsForEntities([]pii_entities.Entity{pii_entities.PhoneNumber})

	config := createTestConfig([]EntityConfig{
		{
			Entity:      "phone_number",
			Enabled:     true,
			MaskWith:    "[MASKED_PHONE]",
			PreserveLen: true,
		},
	}, false)
	// Use a phone number format that won't match the Swift BIC pattern
	example := "+1 (555) 123-4567" // Changed from "+1234567890"
	masked, evt := plugin.maskPlainTextWithRules("Sensitive data: "+example, 0.8, config, keywords, regexRules)
	expected := "Sensitive data: +" + pii_entities.DefaultMasks[pii_entities.PhoneNumber]

	assert.Equal(t, expected, masked, "Phone number masking failed")
	assert.Equal(t, 1, len(evt))
}

func TestMasking_Date(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	regexRules, keywords := buildRegexAndKeywordsForEntities([]pii_entities.Entity{pii_entities.Date})

	config := createTestConfig([]EntityConfig{
		{
			Entity:      "date",
			Enabled:     true,
			MaskWith:    "[MASKED_DATE]",
			PreserveLen: true,
		},
	}, false)

	example := "07/24/2001" // Changed from "+1234567890"
	masked, evt := plugin.maskPlainTextWithRules("Sensitive data: "+example, 0.8, config, keywords, regexRules)
	expected := "Sensitive data: " + pii_entities.DefaultMasks[pii_entities.Date]

	assert.Equal(t, expected, masked, "Date masking failed")
	assert.Equal(t, 1, len(evt))
}

func TestMasking_SSN(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	regexRules, keywords := buildRegexAndKeywordsForEntities([]pii_entities.Entity{pii_entities.SSN})

	config := createTestConfig([]EntityConfig{
		{
			Entity:      "ssn",
			Enabled:     true,
			MaskWith:    "[MASKED_SSN]",
			PreserveLen: true,
		},
	}, false)
	example := "123-45-6789"
	masked, evt := plugin.maskPlainTextWithRules("Sensitive data: "+example, 0.8, config, keywords, regexRules)
	expected := "Sensitive data: " + pii_entities.DefaultMasks[pii_entities.SSN]

	assert.Equal(t, expected, masked, "SSN masking failed")
	assert.Equal(t, 1, len(evt))
}

func TestMasking_IPAddress(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	regexRules, keywords := buildRegexAndKeywordsForEntities([]pii_entities.Entity{pii_entities.IPAddress})

	config := createTestConfig([]EntityConfig{
		{
			Entity:      "ip_address",
			Enabled:     true,
			MaskWith:    "[MASKED_IP]",
			PreserveLen: true,
		},
	}, false)
	example := "192.168.1.1"
	masked, evt := plugin.maskPlainTextWithRules("Sensitive data: "+example, 0.8, config, keywords, regexRules)
	expected := "Sensitive data: " + pii_entities.DefaultMasks[pii_entities.IPAddress]

	assert.Equal(t, expected, masked, "IP address masking failed")
	assert.Equal(t, 1, len(evt))
}

func TestMasking_Password(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	regexRules, keywords := buildRegexAndKeywordsForEntities([]pii_entities.Entity{pii_entities.Password})

	config := createTestConfig([]EntityConfig{
		{
			Entity:      "password",
			Enabled:     true,
			MaskWith:    "[MASKED_PASSWORD]",
			PreserveLen: true,
		},
	}, false)
	example := "password=SuperSecret123"
	masked, evt := plugin.maskPlainTextWithRules("Sensitive data: "+example, 0.8, config, keywords, regexRules)
	expected := "Sensitive data: " + pii_entities.DefaultMasks[pii_entities.Password]

	assert.Equal(t, expected, masked, "Password masking failed")
	assert.Equal(t, 1, len(evt))
}

func TestMasking_APIKey(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	regexRules, keywords := buildRegexAndKeywordsForEntities([]pii_entities.Entity{pii_entities.APIKey})

	config := createTestConfig([]EntityConfig{
		{
			Entity:      "api_key",
			Enabled:     true,
			MaskWith:    "[MASKED_API_KEY]",
			PreserveLen: true,
		},
	}, false)
	example := "api_key=abcd1234efgh5678"
	masked, evt := plugin.maskPlainTextWithRules("Sensitive data: "+example, 0.8, config, keywords, regexRules)
	expected := "Sensitive data: " + pii_entities.DefaultMasks[pii_entities.APIKey]

	assert.Equal(t, expected, masked, "API key masking failed")
	assert.Equal(t, 1, len(evt))
}

func TestMasking_AccessToken(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	regexRules, keywords := buildRegexAndKeywordsForEntities([]pii_entities.Entity{pii_entities.AccessToken})

	config := createTestConfig([]EntityConfig{
		{
			Entity:      "access_token",
			Enabled:     true,
			MaskWith:    "[MASKED_TOKEN]",
			PreserveLen: true,
		},
	}, false)
	example := "access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	masked, evt := plugin.maskPlainTextWithRules("Sensitive data: "+example, 0.8, config, keywords, regexRules)
	expected := "Sensitive data: " + pii_entities.DefaultMasks[pii_entities.AccessToken]

	assert.Equal(t, expected, masked, "Access token masking failed")
	assert.Equal(t, 1, len(evt))
}

func TestMasking_IBAN(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	regexRules, keywords := buildRegexAndKeywordsForEntities([]pii_entities.Entity{pii_entities.IBAN})

	config := createTestConfig([]EntityConfig{
		{
			Entity:      "iban",
			Enabled:     true,
			MaskWith:    "[MASKED_IBAN]",
			PreserveLen: true,
		},
	}, false)
	example := "GB29NWBK60161331926819"
	masked, evt := plugin.maskPlainTextWithRules("Sensitive data: "+example, 0.8, config, keywords, regexRules)
	expected := "Sensitive data: " + pii_entities.DefaultMasks[pii_entities.IBAN]

	assert.Equal(t, expected, masked, "IBAN masking failed")
	assert.Equal(t, 1, len(evt))
}

func TestMasking_CryptoWallet(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	regexRules, keywords := buildRegexAndKeywordsForEntities([]pii_entities.Entity{pii_entities.CryptoWallet})

	config := createTestConfig([]EntityConfig{
		{
			Entity:      "crypto_wallet",
			Enabled:     true,
			MaskWith:    "[MASKED_WALLET]",
			PreserveLen: true,
		},
	}, false)
	example := "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf0a6x"
	masked, evt := plugin.maskPlainTextWithRules("Sensitive data: "+example, 0.8, config, keywords, regexRules)
	expected := "Sensitive data: " + pii_entities.DefaultMasks[pii_entities.CryptoWallet]

	assert.Equal(t, expected, masked, "Crypto wallet masking failed")
	assert.Equal(t, 1, len(evt))
}

func TestMasking_TaxID(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	regexRules, keywords := buildRegexAndKeywordsForEntities([]pii_entities.Entity{pii_entities.TaxID})

	config := createTestConfig([]EntityConfig{
		{
			Entity:      "tax_id",
			Enabled:     true,
			MaskWith:    "[MASKED_TAX_ID]",
			PreserveLen: true,
		},
	}, false)
	example := "12-3456789"
	masked, evt := plugin.maskPlainTextWithRules("Sensitive data: "+example, 0.8, config, keywords, regexRules)
	expected := "Sensitive data: " + pii_entities.DefaultMasks[pii_entities.TaxID]

	assert.Equal(t, expected, masked, "Tax ID masking failed")
	assert.Equal(t, 1, len(evt))
}

func TestMasking_Swift(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	regexRules, keywords := buildRegexAndKeywordsForEntities([]pii_entities.Entity{pii_entities.SwiftBIC})

	config := createTestConfig([]EntityConfig{
		{
			Entity:      "swift_bic",
			Enabled:     true,
			MaskWith:    "[MASKED_BIC]",
			PreserveLen: true,
		},
	}, false)
	example := "DEUTDEFF500"
	masked, evt := plugin.maskPlainTextWithRules("Sensitive data: "+example, 0.8, config, keywords, regexRules)
	expected := "Sensitive data: " + pii_entities.DefaultMasks[pii_entities.SwiftBIC]

	assert.Equal(t, expected, masked, "Tax ID masking failed")
	assert.Equal(t, 1, len(evt))
}

func TestMasking_CreditCard(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	regexRules, keywords := buildRegexAndKeywordsForEntities([]pii_entities.Entity{pii_entities.CreditCard})

	config := createTestConfig([]EntityConfig{
		{
			Entity:      "credit_card",
			Enabled:     true,
			MaskWith:    "[MASKED_CC]",
			PreserveLen: true,
		},
	}, false)
	example := "4111 1111 1111 1111"
	masked, evt := plugin.maskPlainTextWithRules("Sensitive data: "+example, 0.8, config, keywords, regexRules)
	expected := "Sensitive data: " + pii_entities.DefaultMasks[pii_entities.CreditCard]

	assert.Equal(t, expected, masked, "Credit card masking failed")
	assert.Equal(t, 1, len(evt))
}

func TestMasking_Email(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	regexRules, keywords := buildRegexAndKeywordsForEntities([]pii_entities.Entity{pii_entities.Email})

	config := createTestConfig([]EntityConfig{
		{
			Entity:      "email",
			Enabled:     true,
			MaskWith:    "[MASKED_EMAIL]",
			PreserveLen: true,
		},
	}, false)
	example := "test@example.com"
	masked, evt := plugin.maskPlainTextWithRules("Sensitive data: "+example, 0.8, config, keywords, regexRules)
	expected := "Sensitive data: " + pii_entities.DefaultMasks[pii_entities.Email]

	assert.Equal(t, expected, masked, "Email masking failed")
	assert.Equal(t, 1, len(evt))
}

func TestKeywordMasking(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	keywords := map[string]string{"secret": "[MASKED]"}
	regexRules := map[string]*regexp.Regexp{}

	config := createTestConfig([]EntityConfig{}, false)
	masked, evt := plugin.maskPlainTextWithRules("This is a secret", 0.8, config, keywords, regexRules)
	assert.Equal(t, "This is a [MASKED]", masked)
	assert.Equal(t, 1, len(evt))
}

func TestFuzzyMatching(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	regexRules := map[string]*regexp.Regexp{}
	keywords := map[string]string{"secret": "[MASKED_SECRET]"}

	// Test with fuzzy matching enabled
	config := Config{
		SimilarityThreshold: 0.7,
		MaxEditDistance:     1,
		NormalizeInput:      true,
		PredefinedEntities: []EntityConfig{
			{
				Entity:      "credit_card",
				Enabled:     true,
				MaskWith:    "[MASKED_CC]",
				PreserveLen: true,
			},
			{
				Entity:      "ssn",
				Enabled:     true,
				MaskWith:    "[MASKED_SSN]",
				PreserveLen: true,
			},
		},
	}

	// Test similar keyword
	masked, _ := plugin.maskPlainTextWithRules("This is a sekret", 0.7, config, keywords, regexRules)
	assert.Equal(t, "This is a [MASKED_SECRET]", masked, "Fuzzy keyword matching failed")

	// Test credit card with character substitution (O instead of 0)
	// For regex-based masks, supply patterns and default masks
	allRR, allKW := buildAllRegexAndKeywords()
	masked, _ = plugin.maskPlainTextWithRules("My card: 4111 1111 1111 1111", 0.8, config, allKW, allRR)
	assert.Contains(t, masked, pii_entities.DefaultMasks[pii_entities.CreditCard], "Fuzzy regex matching with substitution failed")

	// Test with character deletion
	masked, _ = plugin.maskPlainTextWithRules("My SSN is 123-45-6785", 0.8, config, allKW, allRR)
	assert.Contains(t, masked, pii_entities.DefaultMasks[pii_entities.SSN], "Fuzzy regex matching with deletion failed")
}

func TestNormalizedInput(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	allRR, allKW := buildAllRegexAndKeywords()

	// Test with normalization enabled
	config := Config{
		SimilarityThreshold: 0.8,
		MaxEditDistance:     1,
		NormalizeInput:      true,
		ApplyAll:            true,
	}

	// Test credit card with spaces and dashes removed
	example := "4111-1111-1111-1111"
	masked, evt := plugin.maskPlainTextWithRules("Sensitive data: "+example, 0.8, config, allKW, allRR)
	expected := "Sensitive data: " + pii_entities.DefaultMasks[pii_entities.Default]
	assert.Equal(t, expected, masked, "Normalized credit card masking failed")
	assert.Equal(t, 1, len(evt))

	// Test phone number with different format
	example = "(123) 456-7890"
	masked, evt = plugin.maskPlainTextWithRules("Sensitive data: "+example, 0.8, config, allKW, allRR)
	assert.Contains(t, masked, pii_entities.DefaultMasks[pii_entities.Default], "Normalized phone number masking failed")
	assert.Equal(t, 1, len(evt))
}

func TestInternationalPII(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	regexRules, keywords := buildRegexAndKeywordsForEntities([]pii_entities.Entity{pii_entities.SpanishDNI, pii_entities.MexicanCURP, pii_entities.BrazilianCPF})

	config := createTestConfig([]EntityConfig{
		{
			Entity:      "spanish_dni",
			Enabled:     true,
			MaskWith:    pii_entities.DefaultMasks[pii_entities.SpanishDNI],
			PreserveLen: true,
		},
		{
			Entity:      "mexican_curp",
			Enabled:     true,
			MaskWith:    pii_entities.DefaultMasks[pii_entities.MexicanCURP],
			PreserveLen: true,
		},
		{
			Entity:      "brazilian_cpf",
			Enabled:     true,
			MaskWith:    pii_entities.DefaultMasks[pii_entities.BrazilianCPF],
			PreserveLen: true,
		},
	}, false)

	// Test Spanish DNI
	example := "12345678Z"
	masked, evt := plugin.maskPlainTextWithRules("Spanish ID: "+example, 0.8, config, keywords, regexRules)
	assert.Contains(t, masked, pii_entities.DefaultMasks[pii_entities.SpanishDNI], "Spanish DNI masking failed")
	assert.Equal(t, 1, len(evt))

	// Test Mexican CURP
	example = "BADD110313HCMLNS09"
	masked, evt = plugin.maskPlainTextWithRules("Mexican ID: "+example, 0.8, config, keywords, regexRules)
	assert.Contains(t, masked, pii_entities.DefaultMasks[pii_entities.MexicanCURP], "Mexican CURP masking failed")
	assert.Equal(t, 1, len(evt))

	// Test Brazilian CPF
	example = "123.456.789-09"
	masked, evt = plugin.maskPlainTextWithRules("Brazilian CPF: "+example, 0.8, config, keywords, regexRules)
	assert.Contains(t, masked, pii_entities.DefaultMasks[pii_entities.BrazilianCPF], "Brazilian CPF masking failed")
	assert.Equal(t, 1, len(evt))
}

// createTestCache creates a test cache with a TTL map for data masking
func createTestCache(t *testing.T) cache.Client {
	c := cacheMocks.NewClient(t)
	ttlMap := cache.NewTTLMap(5 * time.Minute)
	c.EXPECT().CreateTTLMap(cache.DataMaskingTTLName, 5*time.Minute).Return(ttlMap).Maybe()
	c.EXPECT().GetTTLMap(cache.DataMaskingTTLName).Return(ttlMap).Maybe()
	c.CreateTTLMap(cache.DataMaskingTTLName, 5*time.Minute)
	return c
}

func TestExecutePlugin(t *testing.T) {
	logger := logrus.New()
	testCache := createTestCache(t)
	plugin, ok := NewDataMaskingPlugin(logger, testCache).(*DataMaskingPlugin)
	assert.True(t, ok)

	config := pluginTypes.PluginConfig{
		Settings: map[string]interface{}{
			"rules": []map[string]interface{}{
				{"pattern": "secret", "type": "keyword", "mask_with": "[MASKED]"},
			},
			"normalize_input":      true,
			"fuzzy_regex_matching": true,
			"max_edit_distance":    1,
		},
	}

	req := &types.RequestContext{Body: []byte("This is a secret")}
	resp := &types.ResponseContext{}
	_, err := plugin.Execute(context.Background(), config, req, resp, metrics.NewEventContext("", "", nil))
	assert.NoError(t, err)
	assert.Equal(t, "This is a [MASKED]", string(req.Body))
}

func TestValidateConfig(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	config := pluginTypes.PluginConfig{
		Settings: map[string]interface{}{
			"rules": []map[string]interface{}{
				{"pattern": "password", "type": "keyword", "mask_with": "[MASKED_PASSWORD]"},
			},
			"normalize_input":      true,
			"fuzzy_regex_matching": true,
		},
	}

	err := plugin.ValidateConfig(config)
	assert.NoError(t, err)
}

func TestJSONMasking(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	// for JSON masking use all patterns and masks
	allRR, allKW := buildAllRegexAndKeywords()

	config := createTestConfig([]EntityConfig{
		{
			Entity:      "credit_card",
			Enabled:     true,
			MaskWith:    "[MASKED_CC]",
			PreserveLen: true,
		},
		{
			Entity:      "ssn",
			Enabled:     true,
			MaskWith:    "[MASKED_SSN]",
			PreserveLen: true,
		},
		{
			Entity:      "email",
			Enabled:     true,
			MaskWith:    "[MASKED_EMAIL]",
			PreserveLen: true,
		},
	}, false)

	// Test JSON masking
	jsonData := map[string]interface{}{
		"user": map[string]interface{}{
			"email": "test@example.com",
			"card":  "4111 1111 1111 1111",
			"details": []interface{}{
				"Some text",
				map[string]interface{}{
					"ssn": "123-45-6789",
				},
			},
		},
	}

	maskedJSON, evt := plugin.maskJSONDataWithRules(jsonData, 0.8, config, allKW, allRR)

	assert.Equal(t, 3, len(evt))
	// Check that email was masked
	maskedUser, ok := maskedJSON.(map[string]interface{})["user"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, pii_entities.DefaultMasks[pii_entities.Email], maskedUser["email"])

	// Check that credit card was masked
	assert.Equal(t, pii_entities.DefaultMasks[pii_entities.CreditCard], maskedUser["card"])

	// Check that nested SSN was masked
	maskedDetails, ok := maskedUser["details"].([]interface{})
	assert.True(t, ok)
	assert.True(t, len(maskedDetails) > 0)
	maskedL := maskedDetails[1]
	maskedSSN, ok := maskedL.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, pii_entities.DefaultMasks[pii_entities.SSN], maskedSSN["ssn"])
}

func TestGenerateReversibleHash(t *testing.T) {
	// Test that the same input with the same secret produces the same hash
	secret := "test-secret"
	value := "sensitive-data"

	hash1 := generateReversibleHash(secret, value)
	hash2 := generateReversibleHash(secret, value)

	assert.Equal(t, hash1, hash2, "Same input with same secret should produce the same hash")

	// Test that different inputs produce different hashes
	value2 := "different-data"
	hash3 := generateReversibleHash(secret, value2)

	assert.NotEqual(t, hash1, hash3, "Different inputs should produce different hashes")

	// Test that same input with different secrets produces different hashes
	secret2 := "different-secret"
	hash4 := generateReversibleHash(secret2, value)

	assert.NotEqual(t, hash1, hash4, "Same input with different secrets should produce different hashes")
}

func TestReplaceWithHashes(t *testing.T) {
	// Create test data
	data := map[string]interface{}{
		"user": map[string]interface{}{
			"email": "test@example.com",
			"card":  "4111 1111 1111 1111",
		},
		"messages": []interface{}{
			"Hello world",
			map[string]interface{}{
				"text": "This contains [MASKED_SSN]",
			},
		},
	}

	// Create masking events
	events := []MaskingEvent{
		{
			Entity:        "email",
			OriginalValue: "test@example.com",
			MaskedWith:    "[MASKED_EMAIL]",
			ReversibleKey: "hash1",
		},
		{
			Entity:        "credit_card",
			OriginalValue: "4111 1111 1111 1111",
			MaskedWith:    "[MASKED_CC]",
			ReversibleKey: "hash2",
		},
		{
			Entity:        "ssn",
			OriginalValue: "123-45-6789",
			MaskedWith:    "[MASKED_SSN]",
			ReversibleKey: "hash3",
		},
	}

	// Replace masked values with hashes
	result := replaceWithHashes(data, events)

	// Verify that masked values were replaced with hashes
	resultMap, ok := result.(map[string]interface{})
	assert.True(t, ok)

	userMap, ok := resultMap["user"].(map[string]interface{})
	assert.True(t, ok)

	assert.Equal(t, "test@example.com", userMap["email"], "Email should not be replaced (not masked yet)")
	assert.Equal(t, "4111 1111 1111 1111", userMap["card"], "Card should not be replaced (not masked yet)")

	// Test with pre-masked data
	maskedData := map[string]interface{}{
		"user": map[string]interface{}{
			"email": "[MASKED_EMAIL]",
			"card":  "[MASKED_CC]",
		},
		"messages": []interface{}{
			"Hello world",
			map[string]interface{}{
				"text": "This contains [MASKED_SSN]",
			},
		},
	}

	// Replace masked values with hashes
	maskedResult := replaceWithHashes(maskedData, events)

	// Verify that masked values were replaced with hashes
	maskedResultMap, ok := maskedResult.(map[string]interface{})
	assert.True(t, ok)

	maskedUserMap, ok := maskedResultMap["user"].(map[string]interface{})
	assert.True(t, ok)

	assert.Equal(t, "hash1", maskedUserMap["email"], "Masked email should be replaced with hash")
	assert.Equal(t, "hash2", maskedUserMap["card"], "Masked card should be replaced with hash")

	messagesArr, ok := maskedResultMap["messages"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, 2, len(messagesArr))

	messageMap, ok := messagesArr[1].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "This contains hash3", messageMap["text"], "Masked SSN should be replaced with hash")
}

func TestRestoreFromHashes(t *testing.T) {
	// Create test data with hashes
	data := map[string]interface{}{
		"user": map[string]interface{}{
			"email": "hash1",
			"card":  "hash2",
		},
		"messages": []interface{}{
			"Hello world",
			map[string]interface{}{
				"text": "This contains hash3",
			},
		},
	}

	// Create hash map
	hashMap := hashToOriginalMap{
		"hash1": "test@example.com",
		"hash2": "4111 1111 1111 1111",
		"hash3": "123-45-6789",
	}

	// Restore original values from hashes
	result := restoreFromHashes(data, hashMap)

	// Verify that hashes were restored to original values
	resultMap, ok := result.(map[string]interface{})
	assert.True(t, ok)

	userMap, ok := resultMap["user"].(map[string]interface{})
	assert.True(t, ok)

	assert.Equal(t, "test@example.com", userMap["email"], "Hash should be restored to original email")
	assert.Equal(t, "4111 1111 1111 1111", userMap["card"], "Hash should be restored to original card")

	messagesArr, ok := resultMap["messages"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, 2, len(messagesArr))

	messageMap, ok := messagesArr[1].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "This contains 123-45-6789", messageMap["text"], "Hash should be restored to original SSN")
}

func TestReversibleHashingWorkflow(t *testing.T) {
	logger := logrus.New()
	testCache := createTestCache(t)
	plugin, ok := NewDataMaskingPlugin(logger, testCache).(*DataMaskingPlugin)
	assert.True(t, ok)

	// Create a configuration with reversible hashing enabled
	config := pluginTypes.PluginConfig{
		Settings: map[string]interface{}{
			"reversible_hashing": map[string]interface{}{
				"enabled": true,
				"secret":  "test-secret",
			},
			"predefined_entities": []map[string]interface{}{
				{
					"entity":    "credit_card",
					"enabled":   true,
					"mask_with": "[MASKED_CC]",
				},
				{
					"entity":    "email",
					"enabled":   true,
					"mask_with": "[MASKED_EMAIL]",
				},
			},
		},
		Stage: pluginTypes.PreRequest,
	}

	// Create a request with sensitive data
	reqBody := []byte(`{
		"user": {
			"email": "test@example.com",
			"card": "4111 1111 1111 1111"
		}
	}`)

	req := &types.RequestContext{Body: reqBody}
	resp := &types.ResponseContext{}

	// Create a shared context for both Execute calls with a traceID
	traceID := "test-trace-id"
	ctx := context.WithValue(context.Background(), common.TraceIdKey, traceID)
	evtCtx := metrics.NewEventContext("", "", nil)

	// Execute the plugin in PreRequest stage
	_, err := plugin.Execute(ctx, config, req, resp, evtCtx)
	assert.NoError(t, err)

	// Verify that the request body was masked and contains hashes
	var maskedData map[string]interface{}
	err = json.Unmarshal(req.Body, &maskedData)
	assert.NoError(t, err)

	userMap, ok := maskedData["user"].(map[string]interface{})
	assert.True(t, ok)

	// The values should now be hashes, not the original values or masked values
	assert.NotEqual(t, "test@example.com", userMap["email"], "Email should be replaced with hash")
	assert.NotEqual(t, "[MASKED_EMAIL]", userMap["email"], "Email should not be the masked value")
	assert.NotEqual(t, "4111 1111 1111 1111", userMap["card"], "Card should be replaced with hash")
	assert.NotEqual(t, "[MASKED_CC]", userMap["card"], "Card should not be the masked value")

	// Now test the PostResponse stage to restore original values
	config.Stage = pluginTypes.PostResponse

	// Create a response with the expected data
	respBody := []byte(`{
		"user": {
			"email": "04d4c4a9449d383577a0488be9bc871181165c41b8ecb4c2a188c89d20341bd4",
			"card": "f115802b1af752aa42602ee67ce70276443f4ba24aba08b762593b9471de43ee"
		}
	}`)
	resp.Body = respBody

	// Execute the plugin in PostResponse stage with the same context
	_, err = plugin.Execute(ctx, config, req, resp, evtCtx)
	assert.NoError(t, err)

	// Verify that the response body was restored to original values
	var restoredData map[string]interface{}
	err = json.Unmarshal(resp.Body, &restoredData)
	assert.NoError(t, err)

	restoredUserMap, ok := restoredData["user"].(map[string]interface{})
	assert.True(t, ok)

	// The values should match the response body
	assert.Equal(t, "test@example.com", restoredUserMap["email"], "Email should match the response body")
	assert.Equal(t, "4111 1111 1111 1111", restoredUserMap["card"], "Card should match the response body")
}
