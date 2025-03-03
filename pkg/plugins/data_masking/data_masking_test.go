package data_masking

import (
	"context"
	"regexp"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

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

func TestMasking_PhoneNumber(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	plugin.regexRules = make(map[string]*regexp.Regexp)

	for entity, pattern := range predefinedEntityPatterns {
		plugin.regexRules[string(entity)] = regexp.MustCompile(pattern)
	}

	example := "+1234567890"
	masked := plugin.maskPlainText("Sensitive data: "+example, 0.8)
	expected := "Sensitive data: " + defaultEntityMasks[PhoneNumber]

	assert.Equal(t, expected, masked, "Phone number masking failed")
}

func TestMasking_SSN(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	plugin.regexRules = make(map[string]*regexp.Regexp)

	for entity, pattern := range predefinedEntityPatterns {
		plugin.regexRules[string(entity)] = regexp.MustCompile(pattern)
	}

	example := "123-45-6789"
	masked := plugin.maskPlainText("Sensitive data: "+example, 0.8)
	expected := "Sensitive data: " + defaultEntityMasks[SSN]

	assert.Equal(t, expected, masked, "SSN masking failed")
}

func TestMasking_IPAddress(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	plugin.regexRules = make(map[string]*regexp.Regexp)

	for entity, pattern := range predefinedEntityPatterns {
		plugin.regexRules[string(entity)] = regexp.MustCompile(pattern)
	}

	example := "192.168.1.1"
	masked := plugin.maskPlainText("Sensitive data: "+example, 0.8)
	expected := "Sensitive data: " + defaultEntityMasks[IPAddress]

	assert.Equal(t, expected, masked, "IP address masking failed")
}

func TestMasking_Password(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	plugin.regexRules = make(map[string]*regexp.Regexp)

	for entity, pattern := range predefinedEntityPatterns {
		plugin.regexRules[string(entity)] = regexp.MustCompile(pattern)
	}

	example := "password=SuperSecret123"
	masked := plugin.maskPlainText("Sensitive data: "+example, 0.8)
	expected := "Sensitive data: " + defaultEntityMasks[Password]

	assert.Equal(t, expected, masked, "Password masking failed")
}

func TestMasking_APIKey(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	plugin.regexRules = make(map[string]*regexp.Regexp)

	for entity, pattern := range predefinedEntityPatterns {
		plugin.regexRules[string(entity)] = regexp.MustCompile(pattern)
	}

	example := "api_key=abcd1234efgh5678"
	masked := plugin.maskPlainText("Sensitive data: "+example, 0.8)
	expected := "Sensitive data: " + defaultEntityMasks[APIKey]

	assert.Equal(t, expected, masked, "API key masking failed")
}

func TestMasking_AccessToken(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	plugin.regexRules = make(map[string]*regexp.Regexp)

	for entity, pattern := range predefinedEntityPatterns {
		plugin.regexRules[string(entity)] = regexp.MustCompile(pattern)
	}

	example := "access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	masked := plugin.maskPlainText("Sensitive data: "+example, 0.8)
	expected := "Sensitive data: " + defaultEntityMasks[AccessToken]

	assert.Equal(t, expected, masked, "Access token masking failed")
}

func TestMasking_IBAN(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	plugin.regexRules = make(map[string]*regexp.Regexp)

	for entity, pattern := range predefinedEntityPatterns {
		plugin.regexRules[string(entity)] = regexp.MustCompile(pattern)
	}

	example := "GB29NWBK60161331926819"
	masked := plugin.maskPlainText("Sensitive data: "+example, 0.8)
	expected := "Sensitive data: " + defaultEntityMasks[IBAN]

	assert.Equal(t, expected, masked, "IBAN masking failed")
}

func TestMasking_SwiftBIC(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	plugin.regexRules = make(map[string]*regexp.Regexp)

	for entity, pattern := range predefinedEntityPatterns {
		plugin.regexRules[string(entity)] = regexp.MustCompile(pattern)
	}

	example := "NWBKGB2LXXX"
	masked := plugin.maskPlainText("Sensitive data: "+example, 0.8)
	expected := "Sensitive data: " + defaultEntityMasks[SwiftBIC]

	assert.Equal(t, expected, masked, "Swift BIC masking failed")
}

func TestMasking_CryptoWallet(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	plugin.regexRules = make(map[string]*regexp.Regexp)

	for entity, pattern := range predefinedEntityPatterns {
		plugin.regexRules[string(entity)] = regexp.MustCompile(pattern)
	}

	example := "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf0a6x"
	masked := plugin.maskPlainText("Sensitive data: "+example, 0.8)
	expected := "Sensitive data: " + defaultEntityMasks[CryptoWallet]

	assert.Equal(t, expected, masked, "Crypto wallet masking failed")
}

func TestMasking_TaxID(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	plugin.regexRules = make(map[string]*regexp.Regexp)

	for entity, pattern := range predefinedEntityPatterns {
		plugin.regexRules[string(entity)] = regexp.MustCompile(pattern)
	}

	example := "12-3456789"
	masked := plugin.maskPlainText("Sensitive data: "+example, 0.8)
	expected := "Sensitive data: " + defaultEntityMasks[TaxID]

	assert.Equal(t, expected, masked, "Tax ID masking failed")
}

func TestMasking_CreditCard(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	plugin.regexRules = make(map[string]*regexp.Regexp)

	for entity, pattern := range predefinedEntityPatterns {
		plugin.regexRules[string(entity)] = regexp.MustCompile(pattern)
	}

	example := "4111 1111 1111 1111"
	masked := plugin.maskPlainText("Sensitive data: "+example, 0.8)
	expected := "Sensitive data: " + defaultEntityMasks[CreditCard]

	assert.Equal(t, expected, masked, "Bank account masking failed")
}

func TestMasking_Email(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	plugin.regexRules = make(map[string]*regexp.Regexp)

	for entity, pattern := range predefinedEntityPatterns {
		plugin.regexRules[string(entity)] = regexp.MustCompile(pattern)
	}

	example := "test@example.com"
	masked := plugin.maskPlainText("Sensitive data: "+example, 0.8)
	expected := "Sensitive data: " + defaultEntityMasks[Email]

	assert.Equal(t, expected, masked, "Bank account masking failed")
}

func TestKeywordMasking(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	plugin.keywords = map[string]string{
		"secret": "[MASKED]",
	}

	masked := plugin.maskPlainText("This is a secret", 0.8)
	assert.Equal(t, "This is a [MASKED]", masked)
}

func TestExecutePlugin(t *testing.T) {
	logger := logrus.New()
	plugin := NewDataMaskingPlugin(logger).(*DataMaskingPlugin)

	config := types.PluginConfig{
		Settings: map[string]interface{}{
			"rules": []map[string]interface{}{
				{"pattern": "secret", "type": "keyword", "mask_with": "[MASKED]"},
			},
		},
	}

	req := &types.RequestContext{Body: []byte("This is a secret")}
	resp := &types.ResponseContext{}
	_, err := plugin.Execute(context.Background(), config, req, resp)
	assert.NoError(t, err)
	assert.Equal(t, "This is a [MASKED]", string(req.Body))
}

func TestValidateConfig(t *testing.T) {
	plugin := &DataMaskingPlugin{}
	config := types.PluginConfig{
		Settings: map[string]interface{}{
			"rules": []map[string]interface{}{
				{"pattern": "password", "type": "keyword", "mask_with": "[MASKED_PASSWORD]"},
			},
		},
	}

	err := plugin.ValidateConfig(config)
	assert.NoError(t, err)
}
