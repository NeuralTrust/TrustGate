package external_api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"

	"github.com/sirupsen/logrus"
)

const (
	PluginName = "external_api"
)

type ExternalApiPlugin struct {
	client *http.Client
}

type FieldMap struct {
	Source      string `mapstructure:"source"`
	Destination string `mapstructure:"destination"`
}

type Condition struct {
	Field          string      `mapstructure:"field"`
	Operator       string      `mapstructure:"operator"`
	Value          interface{} `mapstructure:"value"`
	StopProcessing bool        `mapstructure:"stop_processing"`
	Message        string      `mapstructure:"message"`
}

func (v *ExternalApiPlugin) Name() string {
	return PluginName
}

func (v *ExternalApiPlugin) Stages() []types.Stage {
	return []types.Stage{}
}

func (v *ExternalApiPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest, types.PostResponse}
}

func NewExternalApiPlugin() pluginiface.Plugin {
	return &ExternalApiPlugin{client: &http.Client{}}
}

type ExternalApiValidator struct{}

func (v *ExternalApiValidator) ValidateConfig(config types.PluginConfig) error {
	if config.Stage != types.PreRequest {
		return fmt.Errorf("external validator must be in pre_request stage")
	}

	settings := config.Settings

	// Validate endpoint
	endpoint, ok := settings["endpoint"].(string)
	if !ok || endpoint == "" {
		return fmt.Errorf("external validator requires 'endpoint' configuration")
	}

	// Validate URL format
	if _, err := url.Parse(endpoint); err != nil {
		return fmt.Errorf("invalid endpoint URL format: %v", err)
	}

	// Validate timeout (optional)
	if timeout, exists := settings["timeout"].(string); exists {
		if _, err := time.ParseDuration(timeout); err != nil {
			return fmt.Errorf("invalid timeout format: %v", err)
		}
	}

	return nil
}

func (v *ExternalApiPlugin) Execute(ctx context.Context, cfg types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) (*types.PluginResponse, error) {
	logger, err := getContextValue[*logrus.Logger](ctx, common.LoggerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get logger: %w", err)
	}

	settings := cfg.Settings
	if settings == nil {
		logger.WithError(fmt.Errorf("settings are required")).Error("External validator settings missing")
		return nil, fmt.Errorf("settings are required")
	}
	// Get endpoint
	endpoint, ok := settings["endpoint"].(string)
	if !ok || endpoint == "" {
		return nil, fmt.Errorf("endpoint is required")
	}

	// Get method (default to POST)
	method := "POST"
	if m, ok := settings["method"].(string); ok && m != "" {
		method = m
	}

	// Get headers
	headers := make(map[string]string)
	if h, ok := settings["headers"].(map[string]interface{}); ok {
		for k, v := range h {
			if strVal, ok := v.(string); ok {
				headers[k] = strVal
			}
		}
	}

	// Get timeout (default to 5s)
	timeout := 5 * time.Second
	if t, ok := settings["timeout"].(string); ok && t != "" {
		if parsed, err := time.ParseDuration(t); err == nil {
			timeout = parsed
		}
	}

	// Get field mappings
	var fieldMaps []FieldMap
	if maps, ok := settings["field_maps"].([]interface{}); ok {
		for _, m := range maps {
			if mapData, ok := m.(map[string]interface{}); ok {
				fieldMap := FieldMap{}
				source, err := getStringFromMap(mapData, "source")
				if err != nil {
					return nil, fmt.Errorf("invalid source: %w", err)
				}
				fieldMap.Source = source

				destination, err := getStringFromMap(mapData, "destination")
				if err != nil {
					return nil, fmt.Errorf("invalid destination: %w", err)
				}
				fieldMap.Destination = destination

				fieldMaps = append(fieldMaps, fieldMap)
			}
		}
	}

	// Get conditions
	var conditions []Condition
	if conds, ok := settings["conditions"].([]interface{}); ok {
		for _, c := range conds {
			if condMap, ok := c.(map[string]interface{}); ok {
				condition := Condition{}
				field, err := getStringFromMap(condMap, "field")
				if err != nil {
					return nil, fmt.Errorf("invalid field: %w", err)
				}
				condition.Field = field

				operator, err := getStringFromMap(condMap, "operator")
				if err != nil {
					return nil, fmt.Errorf("invalid operator: %w", err)
				}
				condition.Operator = operator

				stopProcessing, err := getBoolFromMap(condMap, "stop_processing")
				if err != nil {
					return nil, fmt.Errorf("invalid stop_processing: %w", err)
				}
				condition.StopProcessing = stopProcessing

				if msg, ok := condMap["message"].(string); ok {
					condition.Message = msg
				}
				conditions = append(conditions, condition)
			}
		}
	}

	// Parse request body
	var originalBody map[string]interface{}
	if len(req.Body) > 0 {
		if err := json.Unmarshal(req.Body, &originalBody); err != nil {
			return nil, fmt.Errorf("invalid request body: %w", err)
		}
	}

	// Apply field mappings
	validationReq := make(map[string]interface{})
	for _, mapping := range fieldMaps {
		switch mapping.Source {
		case "input":
			if value, ok := originalBody[mapping.Source]; ok {
				validationReq[mapping.Destination] = value
			}
		}
	}

	// Marshal request data
	reqBody, err := json.Marshal(validationReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal validation request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create validation request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}

	// Set timeout
	v.client.Timeout = timeout

	// Make request
	httpResp, err := v.client.Do(httpReq)
	if err != nil {
		return nil, &types.PluginError{
			StatusCode: http.StatusBadGateway,
			Message:    "External validation failed",
			Err:        err,
		}
	}
	defer httpResp.Body.Close()

	// Parse response
	var validationResp map[string]interface{}
	if err := json.NewDecoder(httpResp.Body).Decode(&validationResp); err != nil {
		return nil, fmt.Errorf("failed to parse validation response: %w", err)
	}
	logger.WithFields(logrus.Fields{
		"validationResp": validationResp,
	}).Debug("Validation response")
	// Check conditions
	for _, condition := range conditions {
		value := getNestedValue(validationResp, strings.Split(condition.Field, "."))
		if value != nil {
			if matches := evaluateCondition(value, condition.Operator, condition.Value); matches && condition.StopProcessing {
				return nil, &types.PluginError{
					StatusCode: http.StatusUnprocessableEntity,
					Message:    condition.Message,
					Err:        fmt.Errorf("validation failed"),
				}
			}
		}
	}

	respBody, err := json.Marshal(validationResp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	return &types.PluginResponse{
		StatusCode: http.StatusOK,
		Message:    "Validation passed",
		Body:       respBody,
	}, nil
}

func getNestedValue(data map[string]interface{}, path []string) interface{} {
	current := data
	for i, key := range path {
		if i == len(path)-1 {
			return current[key]
		}
		if next, ok := current[key].(map[string]interface{}); ok {
			current = next
		} else {
			return nil
		}
	}
	return nil
}

func evaluateCondition(actual interface{}, operator string, expected interface{}) bool {
	switch operator {
	case "eq":
		return actual == expected
	case "neq":
		return actual != expected
	case "gt":
		// Convert to float64 for numeric comparison
		actualFloat, aok := actual.(float64)
		expectedFloat, eok := expected.(float64)
		return aok && eok && actualFloat > expectedFloat
	case "lt":
		// Convert to float64 for numeric comparison
		actualFloat, aok := actual.(float64)
		expectedFloat, eok := expected.(float64)
		return aok && eok && actualFloat < expectedFloat
	default:
		return false
	}
}

// Add helper function for safe type assertions
func getContextValue[T any](ctx context.Context, key interface{}) (T, error) {
	value := ctx.Value(key)
	if value == nil {
		var zero T
		return zero, fmt.Errorf("value not found in context for key: %v", key)
	}
	result, ok := value.(T)
	if !ok {
		var zero T
		return zero, fmt.Errorf("invalid type assertion for key: %v", key)
	}
	return result, nil
}

// For map assertions
func getStringFromMap(data map[string]interface{}, key string) (string, error) {
	value, ok := data[key].(string)
	if !ok {
		return "", fmt.Errorf("invalid type assertion for key: %v", key)
	}
	return value, nil
}

// Add helper function for safe bool assertions
func getBoolFromMap(data map[string]interface{}, key string) (bool, error) {
	value, ok := data[key].(bool)
	if !ok {
		return false, fmt.Errorf("invalid type assertion for key: %v", key)
	}
	return value, nil
}
