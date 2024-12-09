package external

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"ai-gateway-ce/internal/types"

	"github.com/sirupsen/logrus"
)

type ExternalValidator struct {
	logger     *logrus.Logger
	endpoint   string
	method     string
	headers    map[string]string
	timeout    time.Duration
	conditions []types.ResponseCondition
	types.BasePlugin
}

type ValidatorConfig struct {
	Endpoint    string                    `json:"endpoint"`
	Method      string                    `json:"method"`
	Headers     map[string]string         `json:"headers"`
	Timeout     string                    `json:"timeout"`
	Conditions  []types.ResponseCondition `json:"conditions"`
	RetryCount  int                       `json:"retry_count"`
	FailOnError bool                      `json:"fail_on_error"`
	FieldMaps   []types.FieldMapping      `json:"field_maps"`
}

type ValidationResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func NewExternalValidator(logger *logrus.Logger, config types.PluginConfig) (*ExternalValidator, error) {
	logger.WithFields(logrus.Fields{
		"config": config,
	}).Debug("Creating external validator with config")

	// Get settings from config
	settings := config.Settings
	if settings == nil {
		return nil, fmt.Errorf("settings are required")
	}

	// Get endpoint
	endpoint, ok := settings["endpoint"].(string)
	if !ok || endpoint == "" {
		return nil, fmt.Errorf("endpoint is required")
	}

	// Get method (default to POST)
	method := "POST"
	if m, ok := settings["method"].(string); ok {
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
	if t, ok := settings["timeout"].(string); ok {
		if parsedTimeout, err := time.ParseDuration(t); err == nil {
			timeout = parsedTimeout
		}
	}

	// Get conditions from settings
	var conditions []types.ResponseCondition
	if configConditions, ok := settings["conditions"].([]interface{}); ok {
		logger.WithFields(logrus.Fields{
			"raw_conditions": configConditions,
		}).Debug("Found conditions in config")

		for _, c := range configConditions {
			if condMap, ok := c.(map[string]interface{}); ok {
				condition := types.ResponseCondition{
					Field:    condMap["field"].(string),
					Operator: condMap["operator"].(string),
					Value:    condMap["value"],
				}
				if stopFlow, ok := condMap["stop_flow"].(bool); ok {
					condition.StopFlow = stopFlow
				}
				if message, ok := condMap["message"].(string); ok {
					condition.Message = message
				}
				conditions = append(conditions, condition)
				logger.WithFields(logrus.Fields{
					"parsed_condition": condition,
				}).Debug("Parsed condition")
			}
		}
	}

	// Parse field mappings using the helper function
	fieldMaps := types.ParseFieldMaps(settings)

	logger.WithFields(logrus.Fields{
		"endpoint":   endpoint,
		"method":     method,
		"headers":    headers,
		"timeout":    timeout,
		"conditions": conditions,
		"field_maps": fieldMaps,
	}).Debug("External validator configuration loaded")

	return &ExternalValidator{
		logger:     logger,
		endpoint:   endpoint,
		method:     method,
		headers:    headers,
		timeout:    timeout,
		conditions: conditions,
		BasePlugin: types.BasePlugin{
			FieldMapper: types.FieldMapper{
				FieldMaps: fieldMaps,
			},
		},
	}, nil
}

func (v *ExternalValidator) Name() string {
	return "external_validator"
}

func (v *ExternalValidator) Priority() int {
	return 2
}

func (v *ExternalValidator) Stage() types.ExecutionStage {
	return types.PreRequest
}

func (v *ExternalValidator) Parallel() bool {
	return true
}

func (v *ExternalValidator) ProcessRequest(reqCtx *types.RequestContext, pluginCtx *types.PluginContext) error {
	var originalBody map[string]interface{}
	if len(reqCtx.Body) > 0 {
		if err := json.Unmarshal(reqCtx.Body, &originalBody); err != nil {
			v.logger.WithError(err).Error("Failed to unmarshal request body")
			return fmt.Errorf("invalid request body: %w", err)
		}
	}

	// Use the field mapper from BasePlugin
	validationPayload := v.MapFields(originalBody)

	// Marshal the validation payload
	payload, err := json.Marshal(validationPayload)
	if err != nil {
		v.logger.WithError(err).Error("Failed to marshal validation payload")
		return fmt.Errorf("failed to create validation payload: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(reqCtx.Context, v.method, v.endpoint, bytes.NewReader(payload))
	if err != nil {
		v.logger.WithError(err).Error("Failed to create validation request")
		return fmt.Errorf("failed to create validation request: %w", err)
	}

	// Set Content-Type header
	req.Header.Set("Content-Type", "application/json")

	// Set all headers from settings
	for headerKey, headerValue := range v.headers {
		req.Header.Set(headerKey, headerValue)
		v.logger.WithFields(logrus.Fields{
			"header": headerKey,
			"value":  headerValue,
		}).Debug("Setting header")
	}

	v.logger.WithFields(logrus.Fields{
		"url":     req.URL.String(),
		"method":  req.Method,
		"headers": req.Header,
		"payload": string(payload),
	}).Debug("Executing validation request")

	// Execute request
	client := &http.Client{Timeout: v.timeout}
	resp, err := client.Do(req)
	if err != nil {
		v.logger.WithError(err).Error("Failed to execute validation request")
		return &types.PluginError{
			StatusCode: http.StatusBadRequest,
			Message:    "Validation request failed",
		}
	}
	defer resp.Body.Close()

	v.logger.WithFields(logrus.Fields{
		"status_code": resp.StatusCode,
	}).Debug("Received validation response")

	// Parse response
	var result map[string]interface{}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		v.logger.WithError(err).Error("Failed to read response body")
		return &types.PluginError{
			StatusCode: http.StatusBadRequest,
			Message:    "Failed to read validation response",
		}
	}

	v.logger.WithFields(logrus.Fields{
		"response_body": string(respBody),
		"conditions":    v.conditions,
	}).Debug("Evaluating response with conditions")

	if err := json.Unmarshal(respBody, &result); err != nil {
		v.logger.WithError(err).Error("Failed to parse validation response")
		return &types.PluginError{
			StatusCode: http.StatusBadRequest,
			Message:    "Invalid validation response format",
		}
	}

	// Check conditions
	for _, condition := range v.conditions {
		v.logger.WithFields(logrus.Fields{
			"condition": condition,
			"result":    result,
			"field":     condition.Field,
			"operator":  condition.Operator,
			"value":     condition.Value,
		}).Debug("Evaluating condition")

		// Split the field path and navigate through the JSON
		fieldPath := strings.Split(condition.Field, ".")
		currentValue := getNestedValue(result, fieldPath, v.logger)

		v.logger.WithFields(logrus.Fields{
			"field_path":    fieldPath,
			"current_value": currentValue,
		}).Debug("Retrieved value for condition")

		if currentValue != nil {
			matched := types.EvaluateCondition(condition, currentValue)
			if matched && condition.StopFlow {
				return &types.PluginError{
					StatusCode: http.StatusOK,
					Message:    condition.Message,
				}
			}
		}
	}

	return nil
}

func (v *ExternalValidator) ProcessResponse(respCtx *types.ResponseContext, pluginCtx *types.PluginContext) error {
	// Add any response processing logic here
	return nil
}

func getNestedValue(data map[string]interface{}, path []string, logger *logrus.Logger) interface{} {
	current := data
	for i, key := range path {
		if i == len(path)-1 {
			return current[key]
		}
		if next, ok := current[key].(map[string]interface{}); ok {
			current = next
		} else {
			logger.WithFields(logrus.Fields{
				"path": path,
				"key":  key,
			}).Debug("Failed to navigate nested value")
			return nil
		}
	}
	return nil
}

// Add Configure method
func (v *ExternalValidator) Configure(config types.PluginConfig) error {
	// Configuration is already handled in NewExternalValidator
	// This is just to satisfy the Plugin interface
	return nil
}

// Add GetName method
func (v *ExternalValidator) GetName() string {
	return "external_validator"
}
