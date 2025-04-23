package request

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/types"
)

const (
	conversationIDKey = "conversation_id"
	interactionIDKey  = "interaction_id"
)

var allowedTLSVersions = map[string]uint16{
	"TLS10": tls.VersionTLS10,
	"TLS11": tls.VersionTLS11,
	"TLS12": tls.VersionTLS12,
	"TLS13": tls.VersionTLS13,
}

type CreateGatewayRequest struct {
	Name            string                            `json:"name"`      // @required
	Subdomain       string                            `json:"subdomain"` // @required
	Status          string                            `json:"status"`
	RequiredPlugins []types.PluginConfig              `json:"required_plugins"`
	Telemetry       *TelemetryRequest                 `json:"telemetry"`
	SecurityConfig  *SecurityConfigRequest            `json:"security_config"`
	TlS             map[string]ClientTLSConfigRequest `json:"client_tls"`
	CreatedAt       time.Time                         `json:"created_at"`
	UpdatedAt       time.Time                         `json:"updated_at"`
}

type TelemetryRequest struct {
	Exporters           []ExporterRequest `json:"exporters"`
	ExtraParams         map[string]string `json:"extra_params"`
	EnablePluginTraces  bool              `json:"enable_plugin_traces"`
	EnableRequestTraces bool              `json:"enable_request_traces"`
	HeaderMapping       map[string]string `json:"header_mapping"`
}

type ExporterRequest struct {
	Name     string                 `json:"name"`
	Settings map[string]interface{} `json:"settings"`
}

type ClientTLSConfigRequest struct {
	AllowInsecureConnections bool                 `json:"allow_insecure_connections"`
	CACert                   string               `json:"ca_cert"`
	ClientCerts              ClientTLSCertRequest `json:"client_certs"`
	CipherSuites             []uint16             `json:"cipher_suites"`
	CurvePreferences         []uint16             `json:"curve_preferences"`
	DisableSystemCAPool      bool                 `json:"disable_system_ca_pool"`
	MinVersion               string               `json:"min_version"`
	MaxVersion               string               `json:"max_version"`
}

type ClientTLSCertRequest struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

type SecurityConfigRequest struct {
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

func (r *CreateGatewayRequest) Validate() error {
	if err := validateTls(r.TlS); err != nil {
		return err
	}

	if r.Telemetry != nil && r.Telemetry.HeaderMapping != nil {
		for key := range r.Telemetry.HeaderMapping {
			if key != conversationIDKey && key != interactionIDKey {
				return fmt.Errorf("invalid key in header_mapping: %s. only '%s' and '%s' are allowed", key, conversationIDKey, interactionIDKey)
			}
		}
	}

	return nil
}

func validateTls(tls map[string]ClientTLSConfigRequest) error {
	for backend, tlsConfig := range tls {
		minVersion, okMin := allowedTLSVersions[tlsConfig.MinVersion]
		maxVersion, okMax := allowedTLSVersions[tlsConfig.MaxVersion]

		if !okMin {
			return fmt.Errorf("invalid min_version in client_tls for backend '%s': %s", backend, tlsConfig.MinVersion)
		}
		if !okMax {
			return fmt.Errorf("invalid max_version in client_tls for backend '%s': %s", backend, tlsConfig.MaxVersion)
		}
		if minVersion > maxVersion {
			return fmt.Errorf("min_version cannot be greater than max_version in client_tls for backend '%s'", backend)
		}

		if tlsConfig.CACert == "" {
			return fmt.Errorf("ca_cert is required in client_tls for backend '%s'", backend)
		}
		if tlsConfig.ClientCerts.Certificate == "" {
			return fmt.Errorf("client_cert.certificate is required in client_tls for backend '%s'", backend)
		}
		if tlsConfig.ClientCerts.PrivateKey == "" {
			return fmt.Errorf("client_cert.private_key is required in client_tls for backend '%s'", backend)
		}

		for _, v := range tlsConfig.CipherSuites {
			if v == 0 {
				return fmt.Errorf("cipher_suites contains invalid value (0) for backend '%s'", backend)
			}
		}
		for _, v := range tlsConfig.CurvePreferences {
			if v == 0 {
				return fmt.Errorf("curve_preferences contains invalid value (0) for backend '%s'", backend)
			}
		}
	}
	return nil
}
