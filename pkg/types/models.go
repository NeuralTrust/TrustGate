package types

import (
	"fmt"
	"time"
)

// Gateway represents a tenant's gateway configuration
type Gateway struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Subdomain       string         `json:"subdomain"`
	Status          string         `json:"status"`
	CreatedAt       string         `json:"created_at"`
	UpdatedAt       string         `json:"updated_at"`
	RequiredPlugins []PluginConfig `json:"required_plugins"`
}

// ForwardingRule represents a rule for forwarding requests
type ForwardingRule struct {
	ID            string            `json:"id"`
	GatewayID     string            `json:"gateway_id"`
	Path          string            `json:"path"`
	ServiceID     string            `json:"service_id"`
	Methods       []string          `json:"methods"`
	Headers       map[string]string `json:"headers"`
	StripPath     bool              `json:"strip_path"`
	PreserveHost  bool              `json:"preserve_host"`
	RetryAttempts int               `json:"retry_attempts"`
	PluginChain   []PluginConfig    `json:"plugin_chain"`
	Active        bool              `json:"active"`
	Public        bool              `json:"public"`
	CreatedAt     string            `json:"created_at"`
	UpdatedAt     string            `json:"updated_at"`
}

type HealthStatus struct {
	Healthy    bool
	LastCheck  time.Time
	LastError  error
	Failures   int
	ActiveConn int32
}

type UpstreamTarget struct {
	ID           string            `json:"id"`
	Weight       int               `json:"weight"`
	Priority     int               `json:"priority"`
	Host         string            `json:"host"`
	Port         int               `json:"port"`
	Protocol     string            `json:"protocol"`
	Provider     string            `json:"provider"`
	Models       []string          `json:"models"`
	DefaultModel string            `json:"default_model"`
	Credentials  Credentials       `json:"credentials"`
	Headers      map[string]string `json:"headers"`
	Path         string            `json:"path"`
	Health       *HealthStatus     `json:"health,omitempty"`
}

// Add validation/initialization method
func (t *UpstreamTarget) Initialize(upstreamID string, index int) {
	if t.ID == "" {
		t.ID = fmt.Sprintf("%s-%s-%d", upstreamID, t.Provider, index)
	}
}

type Credentials struct {
	// Header-based auth
	HeaderName  string `json:"header_name,omitempty"`
	HeaderValue string `json:"header_value,omitempty"`

	// Parameter-based auth
	ParamName     string `json:"param_name,omitempty"`
	ParamValue    string `json:"param_value,omitempty"`
	ParamLocation string `json:"param_location,omitempty"` // "query" or "body"

	// Azure auth
	AzureUseManagedIdentity bool   `json:"azure_use_managed_identity,omitempty"`
	AzureClientID           string `json:"azure_client_id,omitempty"`
	AzureClientSecret       string `json:"azure_client_secret,omitempty"`
	AzureTenantID           string `json:"azure_tenant_id,omitempty"`

	// GCP auth
	GCPUseServiceAccount  bool   `json:"gcp_use_service_account,omitempty"`
	GCPServiceAccountJSON string `json:"gcp_service_account_json,omitempty"`

	// AWS auth
	AWSAccessKeyID     string `json:"aws_access_key_id,omitempty"`
	AWSSecretAccessKey string `json:"aws_secret_access_key,omitempty"`

	// General settings
	AllowOverride bool `json:"allow_override,omitempty"`
}
