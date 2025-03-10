package types

import (
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

type UpdateGatewayRequest struct {
	Name            *string                 `json:"name,omitempty"`
	Status          *string                 `json:"status,omitempty"`
	RequiredPlugins map[string]PluginConfig `json:"required_plugins,omitempty"`
}

type CreateAPIKeyRequest struct {
	Name      string     `json:"name" binding:"required"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type CreateRuleRequest struct {
	Path          string            `json:"path" binding:"required"`
	ServiceID     string            `json:"service_id" binding:"required"`
	Methods       []string          `json:"methods"`
	Headers       map[string]string `json:"headers"`
	StripPath     *bool             `json:"strip_path"`
	PreserveHost  *bool             `json:"preserve_host"`
	RetryAttempts *int              `json:"retry_attempts"`
	PluginChain   []PluginConfig    `json:"plugin_chain"`
}

type UpdateRuleRequest struct {
	Path          string            `json:"path"`
	ServiceID     string            `json:"service_id"`
	Methods       []string          `json:"methods"`
	Headers       map[string]string `json:"headers"`
	StripPath     *bool             `json:"strip_path"`
	PreserveHost  *bool             `json:"preserve_host"`
	RetryAttempts *int              `json:"retry_attempts"`
	Active        *bool             `json:"active"`
	PluginChain   []PluginConfig    `json:"plugin_chain"`
}

// EvaluateCondition evaluates a response condition against a value
func EvaluateCondition(condition ResponseCondition, value interface{}) bool {
	switch condition.Operator {
	case "eq":
		return value == condition.Value
	case "ne":
		return value != condition.Value
	case "gt":
		return compareNumbers(value, condition.Value) > 0
	case "gte":
		return compareNumbers(value, condition.Value) >= 0
	case "lt":
		return compareNumbers(value, condition.Value) < 0
	case "lte":
		return compareNumbers(value, condition.Value) <= 0
	case "contains":
		return containsValue(value, condition.Value)
	case "not_contains":
		return !containsValue(value, condition.Value)
	case "exists":
		return value != nil
	case "not_exists":
		return value == nil
	default:
		return false
	}
}

// Helper functions for condition evaluation
func compareNumbers(a, b interface{}) int {
	var aFloat, bFloat float64

	switch v := a.(type) {
	case int:
		aFloat = float64(v)
	case int32:
		aFloat = float64(v)
	case int64:
		aFloat = float64(v)
	case float32:
		aFloat = float64(v)
	case float64:
		aFloat = v
	default:
		return 0
	}

	switch v := b.(type) {
	case int:
		bFloat = float64(v)
	case int32:
		bFloat = float64(v)
	case int64:
		bFloat = float64(v)
	case float32:
		bFloat = float64(v)
	case float64:
		bFloat = v
	default:
		return 0
	}

	if aFloat < bFloat {
		return -1
	}
	if aFloat > bFloat {
		return 1
	}
	return 0
}

func containsValue(value, searchValue interface{}) bool {
	switch v := value.(type) {
	case string:
		searchStr, ok := searchValue.(string)
		if !ok {
			return false
		}
		return strings.Contains(v, searchStr)
	case []interface{}:
		for _, item := range v {
			if item == searchValue {
				return true
			}
		}
	case map[string]interface{}:
		for _, item := range v {
			if item == searchValue {
				return true
			}
		}
	}
	return false
}

type PluginContext struct {
	Config   PluginConfig
	Redis    *redis.Client
	Logger   *logrus.Logger
	Metadata map[string]interface{}
}

// GatewayData combines gateway and its rules for caching
type GatewayData struct {
	Gateway *Gateway
	Rules   []ForwardingRule
}
