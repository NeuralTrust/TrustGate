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
	PluginName = "toxicity_azure"
)

type ToxicityAzurePlugin struct {
	logger *logrus.Logger
	config Config
}

type Config struct {
	APIKey    string `mapstructure:"api_key"`
	Endpoints struct {
		Text  string `mapstructure:"text"`  // Endpoint for text content
		Image string `mapstructure:"image"` // Endpoint for image content
	} `mapstructure:"endpoints"`
	OutputType       string         `mapstructure:"output_type"`
	CategorySeverity map[string]int `mapstructure:"category_severity"` // Map of category to severity threshold
	Actions          struct {
		Type    string `mapstructure:"type"`
		Message string `mapstructure:"message"`
	} `mapstructure:"actions"`
	ContentTypes []struct {
		Type string `mapstructure:"type"`
		Path string `mapstructure:"path"`
	} `mapstructure:"content_types"`
	Categories []string `mapstructure:"categories"` // Categories to check for (e.g., "Hate", "Violence", etc.)
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

type AzureImageRequest struct {
	Image struct {
		Content string `json:"content"` // base64 encoded image
	} `json:"image"`
	Categories []string `json:"categories"` // categories to analyze
	OutputType string   `json:"outputType"`
}

type AzureImageResponse struct {
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

	// Set default severity levels if not provided
	if cfg.CategorySeverity == nil {
		cfg.CategorySeverity = map[string]int{
			"Hate":     2,
			"Violence": 2,
			"SelfHarm": 2,
			"Sexual":   2,
		}
	}

	// Validate severity levels based on output type
	for category, level := range cfg.CategorySeverity {
		if cfg.OutputType == "FourSeverityLevels" {
			if level != 0 && level != 2 && level != 4 && level != 6 {
				return fmt.Errorf("severity level for category %s must be 0, 2, 4, or 6 for FourSeverityLevels", category)
			}
		} else if level < 0 || level > 7 {
			return fmt.Errorf("severity level for category %s must be between 0 and 7 for EightSeverityLevels", category)
		}
	}

	return nil
}

// extractText attempts to extract text content from various payload formats
func (p *ToxicityAzurePlugin) extractText(rawBody []byte) (string, error) {
	// Find text path from content types
	var textPath string
	for _, ct := range p.config.ContentTypes {
		if ct.Type == "text" {
			textPath = ct.Path
			break
		}
	}

	// If no text path is configured, use the entire request body as text
	if textPath == "" {
		return string(rawBody), nil
	}

	// Try to parse as JSON first
	var data interface{}
	if err := json.Unmarshal(rawBody, &data); err != nil {
		p.logger.WithError(err).Debug("Request body is not JSON, using raw body")
		return string(rawBody), nil
	}

	// Handle different text path formats
	paths := strings.Split(textPath, ".")
	current := data

	for _, path := range paths {
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

	return "", fmt.Errorf("could not extract text from path %s", textPath)
}

// extractImage attempts to extract base64 image content from the request body
func (p *ToxicityAzurePlugin) extractImage(rawBody []byte) (string, error) {
	// Find image path from content types
	var imagePath string
	for _, ct := range p.config.ContentTypes {
		if ct.Type == "image" {
			imagePath = ct.Path
			p.logger.WithField("image_path", imagePath).Info("Found image path in config")
			break
		}
	}

	// If no image path is configured, return error
	if imagePath == "" {
		return "", fmt.Errorf("image path must be specified in content_types for image content")
	}

	// Try to parse as JSON
	var data interface{}
	if err := json.Unmarshal(rawBody, &data); err != nil {
		p.logger.WithError(err).Error("Request body is not valid JSON")
		return "", fmt.Errorf("request body is not valid JSON: %v", err)
	}

	p.logger.WithField("raw_body", string(rawBody)).Debug("Raw request body")

	// Handle different image path formats
	paths := strings.Split(imagePath, ".")
	current := data

	for _, path := range paths {
		p.logger.WithFields(logrus.Fields{
			"current_path": path,
			"data":         fmt.Sprintf("%+v", current),
		}).Debug("Processing path segment")

		if obj, ok := current.(map[string]interface{}); ok {
			current = obj[path]
		} else {
			return "", fmt.Errorf("invalid path at %s", path)
		}
	}

	// Convert final value to string (base64)
	if str, ok := current.(string); ok {
		p.logger.WithField("image_data_length", len(str)).Info("Successfully extracted image data")
		return str, nil
	}

	return "", fmt.Errorf("could not extract base64 image from path %s", imagePath)
}

// getSeverityLevel returns the severity level for a specific category
func (p *ToxicityAzurePlugin) getSeverityLevel(category string) int {
	if level, exists := p.config.CategorySeverity[category]; exists {
		return level
	}
	return 2 // Default severity level if category not configured
}

func (p *ToxicityAzurePlugin) Execute(ctx context.Context, cfg types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) (*types.PluginResponse, error) {
	var config Config
	if err := mapstructure.Decode(cfg.Settings, &config); err != nil {
		p.logger.WithError(err).Error("Failed to decode config")
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}

	p.config = config

	var endpoint string
	var extractedImageData string
	var extractedText string

	// Find the content type we're processing
	var isImageContent bool
	var isTextContent bool
	for _, ct := range config.ContentTypes {
		// Try to extract image data first
		if ct.Type == "image" {
			imageData, err := p.extractImage(req.Body)
			if err == nil {
				isImageContent = true
				endpoint = config.Endpoints.Image
				extractedImageData = imageData
				p.logger.WithField("endpoint", endpoint).Info("Using image endpoint")
				break
			}
		} else if ct.Type == "text" {
			text, err := p.extractText(req.Body)
			if err == nil {
				isTextContent = true
				endpoint = config.Endpoints.Text
				extractedText = text
				p.logger.WithField("endpoint", endpoint).Info("Using text endpoint")
				break
			}
		}
	}

	if !isImageContent && !isTextContent {
		p.logger.Error("No valid content type (text or image) found or could not extract content")
		return &types.PluginResponse{
			StatusCode: 400,
			Message:    "No valid content type (text or image) found or could not extract content",
		}, nil
	}

	// Log configuration
	p.logger.WithFields(logrus.Fields{
		"text_endpoint":     config.Endpoints.Text,
		"image_endpoint":    config.Endpoints.Image,
		"categories":        config.Categories,
		"output_type":       config.OutputType,
		"category_severity": config.CategorySeverity,
		"content_types":     config.ContentTypes,
		"is_image":          isImageContent,
		"is_text":           isTextContent,
		"endpoint":          endpoint,
	}).Info("Starting plugin execution")

	var jsonData []byte
	var err error

	// Handle different content types
	if isImageContent {
		// Create Azure image content safety request
		azureReq := AzureImageRequest{
			Categories: config.Categories,
			OutputType: config.OutputType,
		}
		azureReq.Image.Content = extractedImageData

		jsonData, err = json.Marshal(azureReq)
		if err != nil {
			p.logger.WithError(err).Error("Failed to marshal Azure image request")
			return &types.PluginResponse{
				StatusCode: 500,
				Message:    fmt.Sprintf("Failed to marshal Azure image request: %v", err),
			}, nil
		}
	} else if isTextContent {
		// Use configured categories or default ones
		categories := config.Categories
		if len(categories) == 0 {
			categories = []string{"Hate", "Violence", "SelfHarm", "Sexual"}
		}

		// Create Azure text content safety request
		azureReq := AzureRequest{
			Text:       extractedText,
			Categories: categories,
			OutputType: config.OutputType,
		}

		jsonData, err = json.Marshal(azureReq)
		if err != nil {
			p.logger.WithError(err).Error("Failed to marshal Azure text request")
			return &types.PluginResponse{
				StatusCode: 500,
				Message:    fmt.Sprintf("Failed to marshal Azure text request: %v", err),
			}, nil
		}
	}

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
		"categories":  config.Categories,
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

	// Parse response based on content type
	if isImageContent {
		var azureResp AzureImageResponse
		if err := json.Unmarshal(body, &azureResp); err != nil {
			p.logger.WithFields(logrus.Fields{
				"error":    err.Error(),
				"response": string(body),
			}).Error("Failed to unmarshal Azure image response")
			return &types.PluginResponse{
				StatusCode: 500,
				Message:    fmt.Sprintf("Failed to unmarshal Azure image response: %v, body: %s", err, string(body)),
			}, nil
		}

		// Check severity levels for image content
		var blockedCategories []string
		var analysisResults []map[string]interface{}

		for _, analysis := range azureResp.CategoriesAnalysis {
			severityLevel := p.getSeverityLevel(analysis.Category)

			p.logger.WithFields(logrus.Fields{
				"category":      analysis.Category,
				"severity":      analysis.Severity,
				"severityLevel": severityLevel,
			}).Info("Category analysis")

			// Add result to analysis results
			analysisResults = append(analysisResults, map[string]interface{}{
				"category":      analysis.Category,
				"severity":      analysis.Severity,
				"severityLevel": severityLevel,
			})

			if analysis.Severity >= severityLevel {
				blockedCategories = append(blockedCategories, fmt.Sprintf("%s (severity: %d, threshold: %d)", analysis.Category, analysis.Severity, severityLevel))
			}
		}

		// Create response payload
		responsePayload := map[string]interface{}{
			"analysis_results":   analysisResults,
			"is_blocked":         len(blockedCategories) > 0,
			"blocked_categories": blockedCategories,
		}

		p.logger.WithFields(logrus.Fields{
			"blocked_categories": blockedCategories,
			"is_blocked":         len(blockedCategories) > 0,
			"analysis_results":   analysisResults,
		}).Info("Analysis results")

		// Block request if any category exceeds severity level
		if len(blockedCategories) > 0 {
			message := fmt.Sprintf("Blocked Image Content - Violations found in categories: %s", strings.Join(blockedCategories, ", "))
			p.logger.WithFields(logrus.Fields{
				"blocked_categories": blockedCategories,
				"message":            message,
			}).Info("Image content blocked")

			return nil, &types.PluginError{
				StatusCode: 400,
				Message:    fmt.Sprintf(config.Actions.Message+" Flagged categories: %v", blockedCategories),
				Err:        fmt.Errorf("content flagged for categories: %v", blockedCategories),
			}
		}

		// Marshal the response payload for successful case
		responseBody, err := json.Marshal(responsePayload)
		if err != nil {
			p.logger.WithError(err).Error("Failed to marshal response payload")
			return &types.PluginResponse{
				StatusCode: 500,
				Message:    "Failed to marshal response payload",
			}, nil
		}

		return &types.PluginResponse{
			StatusCode: 200,
			Message:    "Image content is safe",
			Headers: map[string][]string{
				"Content-Type": {"application/json"},
			},
			Body: responseBody,
		}, nil
	}

	// Parse response for text content
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

	// Check severity levels for text content
	var blockedCategories []string
	var analysisResults []map[string]interface{}

	for _, analysis := range azureResp.CategoriesAnalysis {
		severityLevel := p.getSeverityLevel(analysis.Category)

		p.logger.WithFields(logrus.Fields{
			"category":      analysis.Category,
			"severity":      analysis.Severity,
			"severityLevel": severityLevel,
		}).Debug("Category analysis")

		// Add result to analysis results
		analysisResults = append(analysisResults, map[string]interface{}{
			"category":      analysis.Category,
			"severity":      analysis.Severity,
			"severityLevel": severityLevel,
		})

		if analysis.Severity >= severityLevel {
			blockedCategories = append(blockedCategories, fmt.Sprintf("%s (severity: %d, threshold: %d)", analysis.Category, analysis.Severity, severityLevel))
		}
	}

	// Create response payload
	responsePayload := map[string]interface{}{
		"analysis_results":   analysisResults,
		"is_blocked":         len(blockedCategories) > 0,
		"blocked_categories": blockedCategories,
	}

	p.logger.WithFields(logrus.Fields{
		"blocked_categories": blockedCategories,
		"is_blocked":         len(blockedCategories) > 0,
		"analysis_results":   analysisResults,
	}).Info("Analysis results")

	// Block request if any category exceeds severity level
	if len(blockedCategories) > 0 {
		message := fmt.Sprintf("Blocked Text Content - Violations found in categories: %s", strings.Join(blockedCategories, ", "))
		p.logger.WithFields(logrus.Fields{
			"blocked_categories": blockedCategories,
			"message":            message,
		}).Info("Text content blocked")

		return nil, &types.PluginError{
			StatusCode: 400,
			Message:    fmt.Sprintf(config.Actions.Message+" Flagged categories: %v", blockedCategories),
			Err:        fmt.Errorf("content flagged for categories: %v", blockedCategories),
		}
	}

	// Marshal the response payload
	responseBody, err := json.Marshal(responsePayload)
	if err != nil {
		p.logger.WithError(err).Error("Failed to marshal response payload")
		return &types.PluginResponse{
			StatusCode: 500,
			Message:    "Failed to marshal response payload",
		}, nil
	}

	// If no categories exceed severity level, allow the request
	return &types.PluginResponse{
		StatusCode: 200,
		Message:    "Text content is safe",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body: responseBody,
	}, nil
}
