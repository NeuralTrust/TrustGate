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

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/pluginiface"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/google/uuid"

	"github.com/NeuralTrust/TrustGate/pkg/types"
)

const (
	PluginName  = "external_api"
	stopFlowKey = "stop_flow"
)

type ExternalApiPlugin struct {
	client *http.Client
}

type FieldMap struct {
	Source      string `mapstructure:"source"`
	Destination string `mapstructure:"destination"`
}

type Condition struct {
	Field    string      `mapstructure:"field"`
	Operator string      `mapstructure:"operator"`
	Value    interface{} `mapstructure:"value"`
	StopFlow bool        `mapstructure:"stop_flow"`
	Message  string      `mapstructure:"message"`
}

type QueryParam struct {
	Name  string `mapstructure:"name"`
	Value string `mapstructure:"value"`
}

func NewExternalApiPlugin(client *http.Client) pluginiface.Plugin {

	return &ExternalApiPlugin{client: client}
}

func (p *ExternalApiPlugin) Name() string {
	return PluginName
}

func (p *ExternalApiPlugin) RequiredPlugins() []string {
	var requiredPlugins []string
	return requiredPlugins
}

func (p *ExternalApiPlugin) Stages() []pluginTypes.Stage {
	return []pluginTypes.Stage{}
}

func (p *ExternalApiPlugin) AllowedStages() []pluginTypes.Stage {
	return []pluginTypes.Stage{pluginTypes.PreRequest, pluginTypes.PostResponse}
}

func (p *ExternalApiPlugin) SetUp(gatewayID uuid.UUID, config pluginTypes.PluginConfig) error {
	return nil
}

func (p *ExternalApiPlugin) ValidateConfig(config pluginTypes.PluginConfig) error {
	if config.Stage != pluginTypes.PreRequest {
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

	// Validate query parameters
	if params, ok := settings["query_params"].([]interface{}); ok {
		for _, p := range params {
			paramData, ok := p.(map[string]interface{})
			if !ok {
				return fmt.Errorf("invalid query parameter format")
			}

			// Check name field
			name, err := getStringFromMap(paramData, "name")
			if err != nil || name == "" {
				return fmt.Errorf("query parameter must have a non-empty name")
			}

			// Check value field
			_, err = getStringFromMap(paramData, "value")
			if err != nil {
				return fmt.Errorf("query parameter must have a value")
			}
		}
	}

	// Validate timeout (optional)
	if timeout, exists := settings["timeout"].(string); exists {
		if _, err := time.ParseDuration(timeout); err != nil {
			return fmt.Errorf("invalid timeout format: %v", err)
		}
	}

	return nil
}

func (p *ExternalApiPlugin) Execute(
	ctx context.Context,
	cfg pluginTypes.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	evtCtx *metrics.EventContext,
) (*pluginTypes.PluginResponse, error) {

	settings := cfg.Settings
	if settings == nil {
		return nil, fmt.Errorf("settings are required")
	}
	// Get endpoint
	endpoint, ok := settings["endpoint"].(string)
	if !ok || endpoint == "" {
		return nil, fmt.Errorf("endpoint is required")
	}

	// Parse the endpoint URL
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint URL: %v", err)
	}

	// Get query parameters
	queryParams := make(url.Values)
	if params, ok := settings["query_params"].([]interface{}); ok {
		for _, p := range params {
			if paramData, ok := p.(map[string]interface{}); ok {
				name, err := getStringFromMap(paramData, "name")
				if err != nil {
					return nil, fmt.Errorf("invalid query parameter name: %w", err)
				}

				value, err := getStringFromMap(paramData, "value")
				if err != nil {
					return nil, fmt.Errorf("invalid query parameter value: %w", err)
				}

				queryParams.Add(name, value)
			}
		}
	}

	// Add query parameters to the URL
	if len(queryParams) > 0 {
		q := endpointURL.Query()
		for k, values := range queryParams {
			for _, v := range values {
				q.Add(k, v)
			}
		}
		endpointURL.RawQuery = q.Encode()
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

				stopFlow, err := getBoolFromMap(condMap, stopFlowKey)
				if err != nil {
					return nil, fmt.Errorf("invalid %s: %w", stopFlowKey, err)
				}
				condition.StopFlow = stopFlow

				if msg, ok := condMap["message"].(string); ok {
					condition.Message = msg
				}
				if value, ok := condMap["value"]; ok {
					condition.Value = value
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

	// Create HTTP request with the updated URL that includes query parameters
	httpReq, err := http.NewRequestWithContext(ctx, method, endpointURL.String(), bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create validation request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}

	// Set timeout
	p.client.Timeout = timeout
	startTime := time.Now()
	// Make request
	httpResp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, &pluginTypes.PluginError{
			StatusCode: http.StatusBadGateway,
			Message:    "External validation failed",
			Err:        err,
		}
	}
	defer func() { _ = httpResp.Body.Close() }()

	// Parse response
	var validationResp map[string]interface{}
	if err := json.NewDecoder(httpResp.Body).Decode(&validationResp); err != nil {
		return nil, fmt.Errorf("failed to parse validation response: %w", err)
	}

	duration := time.Since(startTime)
	// Check conditions
	for _, condition := range conditions {
		value := getNestedValue(validationResp, strings.Split(condition.Field, "."))
		if value != nil {
			if matches := evaluateCondition(value, condition.Operator, condition.Value); matches && condition.StopFlow {
				evtCtx.SetExtras(ExternalAPIData{
					Endpoint:   endpoint,
					Method:     method,
					StatusCode: http.StatusUnprocessableEntity,
					DurationMs: duration.Milliseconds(),
				})
				return nil, &pluginTypes.PluginError{
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

	evtCtx.SetExtras(ExternalAPIData{
		Endpoint:   endpoint,
		Method:     method,
		StatusCode: httpResp.StatusCode,
		DurationMs: duration.Milliseconds(),
		Response:   string(respBody),
	})
	return &pluginTypes.PluginResponse{
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
