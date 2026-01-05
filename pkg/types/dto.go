package types

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	plugintypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
)

// PluginConfig is an alias for plugintypes.PluginConfig for backward compatibility
type PluginConfig = plugintypes.PluginConfig

// CredentialsDTO represents authentication configuration for upstream services
type CredentialsDTO struct {
	// Api Key
	ApiKey string `json:"api_key,omitempty"`
	// Header-based auth
	HeaderName  string `json:"header_name,omitempty"`
	HeaderValue string `json:"header_value,omitempty"`

	// Parameter-based auth
	ParamName     string `json:"param_name,omitempty"`
	ParamValue    string `json:"param_value,omitempty"`
	ParamLocation string `json:"param_location,omitempty"` // "query" or "body"

	// Azure auth
	AzureUseManagedIdentity bool   `json:"azure_use_managed_identity,omitempty"`
	AzureEndpoint           string `json:"azure_endpoint,omitempty"`
	AzureVersion            string `json:"azure_version,omitempty"`
	AzureClientID           string `json:"azure_client_id,omitempty"`
	AzureClientSecret       string `json:"azure_client_secret,omitempty"`
	AzureTenantID           string `json:"azure_tenant_id,omitempty"`

	// GCP auth
	GCPUseServiceAccount  bool   `json:"gcp_use_service_account,omitempty"`
	GCPServiceAccountJSON string `json:"gcp_service_account_json,omitempty"`

	// AWS auth
	AWSAccessKeyID     string `json:"aws_access_key_id,omitempty"`
	AWSSecretAccessKey string `json:"aws_secret_access_key,omitempty"`
	AWSRegion          string `json:"aws_region,omitempty"`
	AWSSessionToken    string `json:"aws_session_token,omitempty"`
	AWSRole            string `json:"aws_role,omitempty"`
	AWSUseRole         bool   `json:"aws_use_role,omitempty"`
}

func (c *CredentialsDTO) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to scan CredentialsDTO: type assertion to []byte failed")
	}
	return json.Unmarshal(bytes, c)
}

func (c CredentialsDTO) Value() (driver.Value, error) {
	return json.Marshal(c)
}

type GatewayData struct {
	Gateway *GatewayDTO
	Rules   []ForwardingRuleDTO
}

// GatewayDTO represents a tenant's gateway configuration
type GatewayDTO struct {
	ID              string                        `json:"id"`
	Name            string                        `json:"name"`
	Status          string                        `json:"status"`
	RequiredPlugins []PluginConfig                `json:"required_plugins"`
	Telemetry       *TelemetryDTO                 `json:"telemetry"`
	SecurityConfig  *SecurityConfigDTO            `json:"security_config"`
	TlS             map[string]ClientTLSConfigDTO `json:"tls"`
	SessionConfig   *SessionConfigDTO             `json:"session_config,omitempty"`
	CreatedAt       string                        `json:"created_at"`
	UpdatedAt       string                        `json:"updated_at"`
}

type TelemetryDTO struct {
	Exporters           []ExporterDTO     `json:"exporters"`
	ExtraParams         map[string]string `json:"extra_params"`
	EnablePluginTraces  bool              `json:"enable_plugin_traces"`
	EnableRequestTraces bool              `json:"enable_request_traces"`
	HeaderMapping       map[string]string `json:"header_mapping"`
}

type ExporterDTO struct {
	Name     string                 `json:"name"`
	Settings map[string]interface{} `json:"settings"`
}

type SecurityConfigDTO struct {
	AllowedHosts            []string          `json:"allowed_hosts"`
	AllowedHostsAreRegex    bool              `json:"allowed_hosts_are_regex"`
	SSLRedirect             bool              `json:"ssl_redirect"`
	SSLHost                 string            `json:"ssl_host"`
	SSLProxyHeaders         map[string]string `json:"ssl_proxy_headers"`
	STSSeconds              int               `json:"sts_seconds"`
	STSIncludeSubdomains    bool              `json:"sts_include_subdomains"`
	FrameDeny               bool              `json:"frame_deny"`
	CustomFrameOptionsValue string            `json:"custom_frame_options_value"`
	ReferrerPolicy          string            `json:"referrer_policy"`
	ContentSecurityPolicy   string            `json:"content_security_policy"`
	ContentTypeNosniff      bool              `json:"content_type_nosniff"`
	BrowserXSSFilter        bool              `json:"browser_xss_filter"`
	IsDevelopment           bool              `json:"is_development"`
}

type ClientTLSConfigDTO struct {
	AllowInsecureConnections bool             `json:"allow_insecure_connections"`
	CACerts                  string           `json:"ca_certs"`
	ClientCerts              ClientTLSCertDTO `json:"client_certs"`
	CipherSuites             []uint16         `json:"cipher_suites"`
	CurvePreferences         []uint16         `json:"curve_preferences"`
	DisableSystemCAPool      bool             `json:"disable_system_ca_pool"`
	MinVersion               string           `json:"min_version"`
	MaxVersion               string           `json:"max_version"`
}

type ClientTLSCertDTO struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

type SessionConfigDTO struct {
	Enabled        bool   `json:"enabled"`
	HeaderName     string `json:"header_name"`
	BodyParamName  string `json:"body_param_name"`
	QueryParamName string `json:"query_param_name"`
	Mapping        string `json:"mapping"`
	TTL            int    `json:"ttl"`
}

// ForwardingRuleDTO represents a rule for forwarding requests
type ForwardingRuleDTO struct {
	ID            string              `json:"id"`
	Name          string              `json:"name"`
	GatewayID     string              `json:"gateway_id"`
	Path          string              `json:"path"`
	Type          string              `json:"type"`
	ServiceID     string              `json:"service_id"`
	Methods       []string            `json:"methods"`
	Headers       map[string]string   `json:"headers"`
	StripPath     bool                `json:"strip_path"`
	PreserveHost  bool                `json:"preserve_host"`
	RetryAttempts int                 `json:"retry_attempts"`
	PluginChain   []PluginConfig      `json:"plugin_chain"`
	Active        bool                `json:"active"`
	Public        bool                `json:"public"`
	TrustLens     *TrustLensConfigDTO `json:"trustlens,omitempty"`
	CreatedAt     string              `json:"created_at"`
	UpdatedAt     string              `json:"updated_at"`
}

type TrustLensConfigDTO struct {
	AppID   string               `json:"app_id,omitempty"`
	TeamID  string               `json:"team_id,omitempty"`
	Type    string               `json:"type,omitempty"`
	Mapping *TrustLensMappingDTO `json:"mapping,omitempty"`
}

type TrustLensMappingDTO struct {
	Input  TrustLensMappingDataDTO `json:"input"`
	Output TrustLensMappingDataDTO `json:"output"`
}

type TrustLensMappingDataDTO struct {
	ExtractFields  map[string]string `json:"extract_fields"`
	DataProjection map[string]string `json:"data_projection"`
}

type HealthStatusDTO struct {
	Healthy    bool
	LastCheck  time.Time
	LastError  error
	Failures   int
	ActiveConn int32
}

type ProxyDTO struct {
	Host string `json:"host"`
	Port string `json:"port"`
}

type UpstreamDTO struct {
	ID              string              `json:"id"`
	Algorithm       string              `json:"algorithm"`
	EmbeddingConfig *EmbeddingConfigDTO `json:"embedding_config"`
	Targets         []UpstreamTargetDTO `json:"targets"`
	Proxy           *ProxyDTO           `json:"proxy,omitempty"`
}

type EmbeddingConfigDTO struct {
	Provider    string         `json:"provider"`
	Model       string         `json:"model"`
	Credentials CredentialsDTO `json:"credentials,omitempty"`
}

type UpstreamTargetDTO struct {
	ID              string            `json:"id"`
	Weight          int               `json:"weight"`
	Host            string            `json:"host"`
	Port            int               `json:"port"`
	Protocol        string            `json:"protocol"`
	Provider        string            `json:"provider"`
	ProviderOptions map[string]any    `json:"provider_options"`
	Models          []string          `json:"models"`
	DefaultModel    string            `json:"default_model"`
	Description     string            `json:"description"`
	Credentials     CredentialsDTO    `json:"credentials"`
	Headers         map[string]string `json:"headers"`
	Path            string            `json:"path"`
	Health          *HealthStatusDTO  `json:"health,omitempty"`
	Stream          bool              `json:"stream"`
	InsecureSSL     bool              `json:"insecure_ssl,omitempty"`
}
