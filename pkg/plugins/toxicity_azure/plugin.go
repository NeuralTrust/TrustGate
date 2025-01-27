package toxicity_azure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

const (
	PluginName            = "toxicity_azure"
	AzureContentSafetyURL = "https://trustgate.cognitiveservices.azure.com/contentsafety/text:analyze?api-version=2023-10-01"
)

type ToxicityAzurePlugin struct {
	logger *logrus.Logger
	config Config
}

type Config struct {
	APIKey        string `mapstructure:"api_key"`
	AzureEndpoint string `mapstructure:"azure_endpoint"`
	OutputType    string `mapstructure:"output_type"`
	SeverityLevel int    `mapstructure:"severity_level"`
	Actions       struct {
		Type    string `mapstructure:"type"`
		Message string `mapstructure:"message"`
	} `mapstructure:"actions"`
	Categories []string `mapstructure:"categories"` // Categories to check for (e.g., "Hate", "Violence", etc.)
	TextPath   string   `mapstructure:"text_path"`  // JSON path to extract text from (e.g., "text", "messages[].content", "content.text")
}

type RequestBody struct {
	Text     string      `json:"text"`
	Messages []Message   `json:"messages"`
	Content  interface{} `json:"content"`
}

type Message struct {
	Content string `json:"content"`
	Role    string `json:"role"`
}

type AzureRequest struct {
	Text       string   `json:"text"`
	Categories []string `json:"categories"`
	OutputType string   `json:"outputType"`
}

type AzureResponse struct {
	BlocklistsMatch    []string `json:"blocklistsMatch"`
	CategoriesAnalysis []struct {
		Category string `json:"category"`
		Severity int    `json:"severity"`
	} `json:"categoriesAnalysis"`
}

func NewToxicityAzurePlugin(logger *logrus.Logger) pluginiface.Plugin {
	plugin := &ToxicityAzurePlugin{
		logger: logger,
	}
	return plugin
}

func (p *ToxicityAzurePlugin) Name() string {
	return PluginName
}

func (p *ToxicityAzurePlugin) Stages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *ToxicityAzurePlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

// ValidateConfig implements the PluginValidator interface
func (p *ToxicityAzurePlugin) ValidateConfig(config types.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %v", err)
	}

	if cfg.APIKey == "" {
		return fmt.Errorf("Azure API key must be specified")
	}

	if cfg.Actions.Type == "" {
		return fmt.Errorf("action type must be specified")
	}

	if cfg.OutputType == "" {
		cfg.OutputType = "FourSeverityLevels"
	}

	if cfg.OutputType != "FourSeverityLevels" && cfg.OutputType != "EightSeverityLevels" {
		return fmt.Errorf("output type must be either 'FourSeverityLevels' or 'EightSeverityLevels'")
	}

	if cfg.SeverityLevel == 0 {
		cfg.SeverityLevel = 2
	}

	// Validate severity level based on output type
	if cfg.OutputType == "FourSeverityLevels" && (cfg.SeverityLevel != 0 && cfg.SeverityLevel != 2 && cfg.SeverityLevel != 4 && cfg.SeverityLevel != 6) {
		return fmt.Errorf("for FourSeverityLevels, severity level must be 0, 2, 4, or 6")
	}

	if cfg.OutputType == "EightSeverityLevels" && (cfg.SeverityLevel < 0 || cfg.SeverityLevel > 7) {
		return fmt.Errorf("for EightSeverityLevels, severity level must be between 0 and 7")
	}

	return nil
}

// extractText attempts to extract text content from various payload formats
func (p *ToxicityAzurePlugin) extractText(rawBody []byte) (string, error) {
	// If no text path is configured, use the entire request body as text
	if p.config.TextPath == "" {
		return string(rawBody), nil
	}

	// Try to parse as JSON first
	var data interface{}
	if err := json.Unmarshal(rawBody, &data); err != nil {
		p.logger.WithError(err).Debug("Request body is not JSON, using raw body")
		return string(rawBody), nil
	}

	// Handle different text path formats
	paths := strings.Split(p.config.TextPath, ".")
	current := data

	for i, path := range paths {
		// Handle array access (e.g., messages[].content)
		if strings.HasSuffix(path, "[]") {
			fieldName := strings.TrimSuffix(path, "[]")
			arr, ok := current.(map[string]interface{})[fieldName].([]interface{})
			if !ok {
				return "", fmt.Errorf("invalid array path at %s", p.config.TextPath)
			}

			// If this is the last path component, join all values
			if i == len(paths)-1 {
				var texts []string
				for _, item := range arr {
					if str, ok := item.(string); ok {
						texts = append(texts, str)
					}
				}
				return strings.Join(texts, " "), nil
			}

			// If there's a next path component, collect all values at that path
			if i+1 < len(paths) {
				var texts []string
				nextField := paths[i+1]
				for _, item := range arr {
					if obj, ok := item.(map[string]interface{}); ok {
						if val, ok := obj[nextField].(string); ok {
							texts = append(texts, val)
						}
					}
				}
				return strings.Join(texts, " "), nil
			}
		}

		// Handle regular object access
		if obj, ok := current.(map[string]interface{}); ok {
			current = obj[path]
		} else {
			return "", fmt.Errorf("invalid path at %s", path)
		}
	}

	// Convert final value to string
	switch v := current.(type) {
	case string:
		return v, nil
	case []interface{}:
		var texts []string
		for _, item := range v {
			if str, ok := item.(string); ok {
				texts = append(texts, str)
			}
		}
		return strings.Join(texts, " "), nil
	case map[string]interface{}:
		if text, ok := v["text"].(string); ok {
			return text, nil
		}
		if content, ok := v["content"].(string); ok {
			return content, nil
		}
	}

	return "", fmt.Errorf("could not extract text from path %s", p.config.TextPath)
}

func (p *ToxicityAzurePlugin) Execute(ctx context.Context, cfg types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) (*types.PluginResponse, error) {
	var config Config
	if err := mapstructure.Decode(cfg.Settings, &config); err != nil {
		p.logger.WithError(err).Error("Failed to decode config")
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}

	p.config = config

	// Validate and construct endpoint URL
	endpoint := config.AzureEndpoint
	if endpoint == "" {
		p.logger.Error("Azure endpoint is required but not provided")
		return &types.PluginResponse{
			StatusCode: 400,
			Message:    "Azure endpoint is required but not provided",
		}, nil
	}

	p.logger.WithFields(logrus.Fields{
		"endpoint":       endpoint,
		"categories":     config.Categories,
		"output_type":    config.OutputType,
		"severity_level": config.SeverityLevel,
	}).Debug("Plugin configuration")

	// Log raw request body for debugging
	p.logger.WithField("raw_body", string(req.Body)).Debug("Received request body")

	// Extract text content from the request body
	text, err := p.extractText(req.Body)
	if err != nil {
		p.logger.WithError(err).Error("Failed to extract text from request body")
		return &types.PluginResponse{
			StatusCode: 400,
			Message:    err.Error(),
		}, nil
	}

	if text == "" {
		p.logger.Info("No content to analyze")
		return &types.PluginResponse{
			StatusCode: 200,
			Message:    "No content to analyze",
		}, nil
	}

	p.logger.WithField("text", text).Debug("Content to analyze")

	// Use configured categories or default ones
	categories := config.Categories
	if len(categories) == 0 {
		categories = []string{"Hate", "Violence", "SelfHarm", "Sexual"}
	}

	// Create Azure content safety request
	azureReq := AzureRequest{
		Text:       text,
		Categories: categories,
		OutputType: config.OutputType,
	}

	jsonData, err := json.Marshal(azureReq)
	if err != nil {
		p.logger.WithError(err).Error("Failed to marshal Azure request")
		return &types.PluginResponse{
			StatusCode: 500,
			Message:    fmt.Sprintf("Failed to marshal Azure request: %v", err),
		}, nil
	}

	p.logger.WithFields(logrus.Fields{
		"endpoint":    endpoint,
		"request":     string(jsonData),
		"categories":  categories,
		"output_type": config.OutputType,
	}).Debug("Sending request to Azure")

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		p.logger.WithError(err).Error("Failed to create HTTP request")
		return &types.PluginResponse{
			StatusCode: 500,
			Message:    fmt.Sprintf("Failed to create HTTP request: %v", err),
		}, nil
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Ocp-Apim-Subscription-Key", config.APIKey)

	// Send request
	client := &http.Client{}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		p.logger.WithError(err).Error("Failed to send request to Azure")
		return &types.PluginResponse{
			StatusCode: 500,
			Message:    fmt.Sprintf("Failed to send request to Azure: %v", err),
		}, nil
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		p.logger.WithError(err).Error("Failed to read response body")
		return &types.PluginResponse{
			StatusCode: 500,
			Message:    fmt.Sprintf("Failed to read response body: %v", err),
		}, nil
	}

	p.logger.WithFields(logrus.Fields{
		"status_code": httpResp.StatusCode,
		"response":    string(body),
	}).Debug("Received response from Azure")

	if httpResp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf("Azure API returned error (status: %d): %s", httpResp.StatusCode, string(body))
		p.logger.Error(errMsg)
		return &types.PluginResponse{
			StatusCode: httpResp.StatusCode,
			Message:    errMsg,
		}, nil
	}

	// Parse response
	var azureResp AzureResponse
	if err := json.Unmarshal(body, &azureResp); err != nil {
		p.logger.WithFields(logrus.Fields{
			"error":    err.Error(),
			"response": string(body),
		}).Error("Failed to unmarshal Azure response")
		return &types.PluginResponse{
			StatusCode: 500,
			Message:    fmt.Sprintf("Failed to unmarshal Azure response: %v, body: %s", err, string(body)),
		}, nil
	}

	if len(azureResp.CategoriesAnalysis) == 0 {
		p.logger.WithField("response", string(body)).Error("No categories analysis returned")
		return &types.PluginResponse{
			StatusCode: 500,
			Message:    fmt.Sprintf("No categories analysis returned in response: %s", string(body)),
		}, nil
	}

	// Check if any category exceeds severity level
	var blockedCategories []string
	for _, analysis := range azureResp.CategoriesAnalysis {
		p.logger.WithFields(logrus.Fields{
			"category":      analysis.Category,
			"severity":      analysis.Severity,
			"severityLevel": config.SeverityLevel,
		}).Debug("Category analysis")

		if analysis.Severity > config.SeverityLevel {
			blockedCategories = append(blockedCategories, fmt.Sprintf("%s (severity: %d)", analysis.Category, analysis.Severity))
		}
	}

	// Convert Azure response to JSON for the response body
	jsonResponse, err := json.Marshal(azureResp)
	if err != nil {
		p.logger.WithError(err).Error("Failed to marshal response")
		return &types.PluginResponse{
			StatusCode: 500,
			Message:    fmt.Sprintf("Failed to marshal response: %v", err),
		}, nil
	}

	// Block request if any category exceeds severity level
	if len(blockedCategories) > 0 {
		message := fmt.Sprintf("Blocked Content - Violations found in categories: %s", strings.Join(blockedCategories, ", "))
		p.logger.WithFields(logrus.Fields{
			"blocked_categories": blockedCategories,
			"message":            message,
		}).Info("Content blocked")

		return nil, &types.PluginError{
			StatusCode: 400,
			Message:    fmt.Sprintf(config.Actions.Message+" Flagged categories: %v", blockedCategories),
			Err:        fmt.Errorf("content flagged for categories: %v", blockedCategories),
		}
	}

	// If no categories exceed severity level, allow the request
	return &types.PluginResponse{
		StatusCode: 200,
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body: jsonResponse,
	}, nil
}
