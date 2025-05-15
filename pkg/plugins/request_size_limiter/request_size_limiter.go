package request_size_limiter

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

const (
	PluginName = "request_size_limiter"
)

// SizeUnit represents the unit for size measurement
type SizeUnit string

const (
	Bytes     SizeUnit = "bytes"
	Kilobytes SizeUnit = "kilobytes"
	Megabytes SizeUnit = "megabytes"
)

// Config represents the configuration for the request size limiter plugin
type Config struct {
	// Byte-based limits
	AllowedPayloadSize int      `mapstructure:"allowed_payload_size"` // Maximum allowed payload size in bytes/KB/MB
	SizeUnit           SizeUnit `mapstructure:"size_unit"`            // Unit for size measurement

	// Character-based limits
	MaxCharsPerRequest int64 `mapstructure:"max_chars_per_request"` // Maximum characters allowed per request

	// Options
	RequireContentLength bool `mapstructure:"require_content_length"` // Whether to require Content-Length header
}

// RequestSizeLimiterPlugin implements request size limiting
type RequestSizeLimiterPlugin struct {
	logger *logrus.Logger
}

// NewRequestSizeLimiterPlugin creates a new instance of the request size limiter plugin
func NewRequestSizeLimiterPlugin(logger *logrus.Logger) pluginiface.Plugin {
	return &RequestSizeLimiterPlugin{
		logger: logger,
	}
}

// Name returns the name of the plugin
func (p *RequestSizeLimiterPlugin) Name() string {
	return PluginName
}

func (p *RequestSizeLimiterPlugin) RequiredPlugins() []string {
	var requiredPlugins []string
	return requiredPlugins
}

// Stages returns the fixed stages where this plugin must run
func (p *RequestSizeLimiterPlugin) Stages() []types.Stage {
	return []types.Stage{}
}

// AllowedStages returns all stages where this plugin is allowed to run
func (p *RequestSizeLimiterPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

// ValidateConfig validates the plugin configuration
func (p *RequestSizeLimiterPlugin) ValidateConfig(config types.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %v", err)
	}

	// Validate allowed payload size
	if cfg.AllowedPayloadSize <= 0 {
		return fmt.Errorf("allowed_payload_size must be greater than 0")
	}

	// Validate size unit if provided
	if cfg.SizeUnit != "" && cfg.SizeUnit != Bytes && cfg.SizeUnit != Kilobytes && cfg.SizeUnit != Megabytes {
		return fmt.Errorf("size_unit must be one of: bytes, kilobytes, megabytes")
	}

	// Validate character limits
	if cfg.MaxCharsPerRequest < 0 {
		return fmt.Errorf("max_chars_per_request cannot be negative")
	}

	return nil
}

// Execute implements the request size limiting logic
func (p *RequestSizeLimiterPlugin) Execute(
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

	// Set defaults
	if config.SizeUnit == "" {
		config.SizeUnit = Megabytes
	}
	if config.AllowedPayloadSize <= 0 {
		config.AllowedPayloadSize = 10 // Default to 10MB
	}
	if config.MaxCharsPerRequest <= 0 {
		config.MaxCharsPerRequest = 100000 // Default to 100K characters per request
	}

	// Check Content-Length requirement
	if config.RequireContentLength {
		contentLength := ""
		if contentLengthHeaders, ok := req.Headers["Content-Length"]; ok && len(contentLengthHeaders) > 0 {
			contentLength = contentLengthHeaders[0]
		}

		if contentLength == "" {
			return nil, &types.PluginError{
				StatusCode: 411, // Length Required
				Message:    "Content-Length header is required",
			}
		}
	}

	// Calculate size limit in bytes
	var maxSizeBytes int
	switch config.SizeUnit {
	case Bytes:
		maxSizeBytes = config.AllowedPayloadSize
	case Kilobytes:
		maxSizeBytes = config.AllowedPayloadSize * 1024
	case Megabytes:
		maxSizeBytes = config.AllowedPayloadSize * 1024 * 1024
	}

	// Get request size in bytes
	byteSize := len(req.Body)

	// Check byte size limit
	if byteSize > maxSizeBytes {
		p.logger.WithFields(logrus.Fields{
			"request_size_bytes": byteSize,
			"max_size_bytes":     maxSizeBytes,
			"size_unit":          config.SizeUnit,
		}).Warn("Request size limit exceeded")

		evtCtx.SetError(errors.New("request size limit exceeded"))
		evtCtx.SetExtras(RequestSizeLimiterData{
			RequestSizeBytes: byteSize,
			MaxSizeBytes:     maxSizeBytes,
			LimitExceeded:    true,
			ExceededType:     "bytes",
		})
		return nil, &types.PluginError{
			StatusCode: 413, // Payload Too Large
			Message:    fmt.Sprintf("Request size limit exceeded. Received: %d bytes", byteSize),
		}
	}

	// Count characters
	charCount := len(string(req.Body))

	// Check per-request character limit
	if charCount > int(config.MaxCharsPerRequest) {
		p.logger.WithFields(logrus.Fields{
			"char_count":            charCount,
			"max_chars_per_request": config.MaxCharsPerRequest,
		}).Warn("Character limit per request exceeded")
		evtCtx.SetError(errors.New("request size limit exceeded"))
		evtCtx.SetExtras(RequestSizeLimiterData{
			RequestSizeChars:   charCount,
			MaxCharsPerRequest: int(config.MaxCharsPerRequest),
			LimitExceeded:      true,
			ExceededType:       "chars",
		})
		return nil, &types.PluginError{
			StatusCode: 413, // Payload Too Large
			Message:    fmt.Sprintf("Character limit exceeded. Received: %d characters", charCount),
		}
	}

	// Prepare response headers
	headers := map[string][]string{
		"X-Request-Size-Bytes": {strconv.Itoa(byteSize)},
		"X-Request-Size-Chars": {strconv.Itoa(charCount)},
		"X-Size-Limit-Bytes":   {strconv.Itoa(maxSizeBytes)},
		"X-Size-Limit-Chars":   {strconv.FormatInt(config.MaxCharsPerRequest, 10)},
	}

	evtCtx.SetExtras(RequestSizeLimiterData{
		RequestSizeChars:   charCount,
		MaxCharsPerRequest: int(config.MaxCharsPerRequest),
		LimitExceeded:      false,
	})

	return &types.PluginResponse{
		StatusCode: 200,
		Headers:    headers,
	}, nil
}

// countJSONCharacters recursively counts characters in JSON data
func (p *RequestSizeLimiterPlugin) countJSONCharacters(data interface{}) int {
	switch v := data.(type) {
	case map[string]interface{}:
		count := 0
		for _, value := range v {
			count += p.countJSONCharacters(value)
		}
		return count
	case []interface{}:
		count := 0
		for _, item := range v {
			count += p.countJSONCharacters(item)
		}
		return count
	case string:
		return len(v)
	default:
		// For numbers, booleans, etc., convert to string and count
		return len(fmt.Sprintf("%v", v))
	}
}

// removeWhitespace removes all whitespace from a string
func removeWhitespace(s string) string {
	var result []rune
	for _, r := range s {
		if !isWhitespace(r) {
			result = append(result, r)
		}
	}
	return string(result)
}

// isWhitespace checks if a rune is whitespace
func isWhitespace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r'
}

// removeSpecialChars removes special characters based on a pattern
func removeSpecialChars(s string, pattern string) string {
	// This is a simplified implementation
	result := s
	for _, c := range []string{".", ",", "!", "?", ";", ":", "-", "_", "(", ")", "[", "]", "{", "}", "<", ">", "/", "\\", "|", "@", "#", "$", "%", "^", "&", "*", "+", "="} {
		result = strings.ReplaceAll(result, c, "")
	}
	return result
}
