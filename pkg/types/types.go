package types

import (
	"time"
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

type CreateGatewayRequest struct {
	Name            string         `json:"name"`
	Subdomain       string         `json:"subdomain" gorm:"uniqueIndex"`
	Status          string         `json:"status"`
	RequiredPlugins []PluginConfig `json:"required_plugins" gorm:"type:jsonb"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

type ServiceRequest struct {
	ID          string   `json:"id" gorm:"primaryKey"`
	GatewayID   string   `json:"gateway_id" gorm:"not null"`
	Name        string   `json:"name" gorm:"uniqueIndex:idx_gateway_service_name"`
	Type        string   `json:"type" gorm:"not null"`
	Description string   `json:"description"`
	Tags        []string `json:"tags,omitempty" gorm:"type:jsonb"`

	UpstreamID string `json:"upstream_id,omitempty"`

	Host        string            `json:"host,omitempty"`
	Port        int               `json:"port,omitempty"`
	Protocol    string            `json:"protocol,omitempty"`
	Path        string            `json:"path,omitempty"`
	Headers     map[string]string `json:"headers,omitempty" gorm:"type:jsonb"`
	Credentials Credentials       `json:"credentials,omitempty" gorm:"type:jsonb"`

	Retries   int `json:"retries,omitempty"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type UpstreamRequest struct {
	ID           string              `json:"id"`
	GatewayID    string              `json:"gateway_id"`
	Name         string              `json:"name"`
	Algorithm    string              `json:"algorithm"`
	Targets      []TargetRequest     `json:"targets"`
	HealthChecks *HealthCheckRequest `json:"health_checks,omitempty"`
	Tags         []string            `json:"tags,omitempty"`
}

type TargetRequest struct {
	ID           string            `json:"id"`
	Weight       int               `json:"weight,omitempty"`
	Priority     int               `json:"priority,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Path         string            `json:"path,omitempty"`
	Host         string            `json:"host,omitempty"`
	Port         int               `json:"port,omitempty"`
	Protocol     string            `json:"protocol,omitempty"`
	Provider     string            `json:"provider,omitempty"`
	Models       []string          `json:"models,omitempty"`
	DefaultModel string            `json:"default_model,omitempty"`
	Credentials  Credentials       `json:"credentials,omitempty"`
}

type HealthCheckRequest struct {
	Passive   bool              `json:"passive"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers"`
	Threshold int               `json:"threshold"` // Number of failures before marking as unhealthy
	Interval  int               `json:"interval"`  // Time in seconds before resetting failure count

}

// GatewayData combines gateway and its rules for caching
type GatewayData struct {
	Gateway *Gateway
	Rules   []ForwardingRule
}
