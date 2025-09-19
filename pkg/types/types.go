package types

import (
	"time"
)

type CreateRuleRequest struct {
	Path          string            `json:"path" binding:"required"`
	Name          string            `json:"name" binding:"required"`
	ServiceID     string            `json:"service_id" binding:"required"`
	Methods       []string          `json:"methods"`
	Headers       map[string]string `json:"headers"`
	StripPath     *bool             `json:"strip_path"`
	PreserveHost  *bool             `json:"preserve_host"`
	RetryAttempts *int              `json:"retry_attempts"`
	PluginChain   []PluginConfig    `json:"plugin_chain"`
	TrustLens     *TrustLensConfig  `json:"trustlens,omitempty"`
}

type UpdateRuleRequest struct {
	Path          string            `json:"path"`
	Name          string            `json:"name"`
	ServiceID     string            `json:"service_id"`
	Methods       []string          `json:"methods"`
	Headers       map[string]string `json:"headers"`
	StripPath     *bool             `json:"strip_path"`
	PreserveHost  *bool             `json:"preserve_host"`
	RetryAttempts *int              `json:"retry_attempts"`
	Active        *bool             `json:"active"`
	PluginChain   []PluginConfig    `json:"plugin_chain"`
	TrustLens     *TrustLensConfig  `json:"trust_lens,omitempty"`
}

type ServiceRequest struct {
	ID          string   `json:"id"`
	GatewayID   string   `json:"gateway_id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Tags        []string `json:"tags,omitempty"`

	UpstreamID string `json:"upstream_id,omitempty"`

	Host        string            `json:"host,omitempty"`
	Port        int               `json:"port,omitempty"`
	Protocol    string            `json:"protocol,omitempty"`
	Path        string            `json:"path,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Credentials Credentials       `json:"credentials,omitempty"`

	Retries   int `json:"retries,omitempty"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// GatewayData combines gateway and its rules for caching
type GatewayData struct {
	Gateway *Gateway
	Rules   []ForwardingRule
}
