package request

import (
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/openai"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type ProxyConfigRequest struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
}

type UpstreamRequest struct {
	ID            string                `json:"id"`
	GatewayID     string                `json:"gateway_id"`
	Name          string                `json:"name"`
	Algorithm     string                `json:"algorithm"`
	Targets       []TargetRequest       `json:"targets"`
	Embedding     *EmbeddingRequest     `json:"embedding,omitempty"`
	HealthChecks  *HealthCheckRequest   `json:"health_checks,omitempty"`
	Tags          []string              `json:"tags,omitempty"`
	WebhookConfig *WebhookConfigRequest `json:"websocket_config,omitempty"`
	ProxyConfig   *ProxyConfigRequest   `json:"proxy_config,omitempty"`
}

type EmbeddingRequest struct {
	Provider    string            `json:"provider"`
	Model       string            `json:"model"`
	Credentials types.Credentials `json:"credentials,omitempty"`
}

type TargetRequest struct {
	ID              string            `json:"id"`
	Weight          int               `json:"weight,omitempty"`
	Tags            []string          `json:"tags,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	Path            string            `json:"path,omitempty"`
	Host            string            `json:"host,omitempty"`
	Port            int               `json:"port,omitempty"`
	Protocol        string            `json:"protocol,omitempty"`
	Provider        string            `json:"provider,omitempty"`
	ProviderOptions map[string]any    `json:"provider_options,omitempty"`
	Models          []string          `json:"models,omitempty"`
	DefaultModel    string            `json:"default_model,omitempty"`
	Description     string            `json:"description,omitempty"`
	Stream          bool              `json:"stream"`
	InsecureSSL     bool              `json:"insecure_ssl,omitempty"`
	Credentials     types.Credentials `json:"credentials,omitempty"`
}

type HealthCheckRequest struct {
	Passive   bool              `json:"passive"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers"`
	Threshold int               `json:"threshold"` // Number of failures before marking as unhealthy
	Interval  int               `json:"interval"`  // Time in seconds before resetting failure count

}

type WebhookConfigRequest struct {
	EnableDirectCommunication bool   `json:"enable_direct_communication"`
	ReturnErrorDetails        bool   `json:"return_error_details"`
	PingPeriod                string `json:"ping_period"`
	PongWait                  string `json:"pong_wait"`
	HandshakeTimeout          string `json:"handshake_timeout"`
	ReadBufferSize            int    `json:"read_buffer_size"`
	WriteBufferSize           int    `json:"write_buffer_size"`
}

func (r *WebhookConfigRequest) Validate() error {
	if r.PingPeriod != "" {
		if _, err := time.ParseDuration(r.PingPeriod); err != nil {
			return fmt.Errorf("invalid ping_period format: %w", err)
		}
	}
	if r.PongWait != "" {
		if _, err := time.ParseDuration(r.PongWait); err != nil {
			return fmt.Errorf("invalid pong_wait format: %w", err)
		}
	}
	if r.HandshakeTimeout != "" {
		if _, err := time.ParseDuration(r.HandshakeTimeout); err != nil {
			return fmt.Errorf("invalid handshake_timeout format: %w", err)
		}
	}
	if r.ReadBufferSize < 0 {
		return fmt.Errorf("read_buffer_size must be a positive value")
	}
	if r.WriteBufferSize < 0 {
		return fmt.Errorf("write_buffer_size must be a positive value")
	}
	return nil
}

func (r *UpstreamRequest) Validate() error {
	for i, target := range r.Targets {
		if target.Provider != "" {
			if !r.isValidProvider(target.Provider) {
				return fmt.Errorf("target %d: invalid provider: %s", i, target.Provider)
			}
			if target.Path != "" {
				return fmt.Errorf("target %d: when target has provider specified, path must be empty", i)
			}
		}
		if len(target.ProviderOptions) > 0 && target.Provider == "" {
			return fmt.Errorf("target %d: provider_options can only be set when provider is specified", i)
		}

		if err := r.validateProviderOptions(i, target, len(r.Targets)); err != nil {
			return err
		}
	}

	if r.Algorithm == common.SemanticStrategyName {
		for i, target := range r.Targets {
			if target.Description == "" {
				return fmt.Errorf("target %d: description is required", i)
			}
			if !r.isValidProvider(target.Provider) {
				return fmt.Errorf("invalid target provider: %s", target.Provider)
			}
		}
		if r.Embedding == nil {
			return fmt.Errorf("embedding configuration is required when algorithm is semantic")
		}
		if r.Embedding.Model == "" {
			return fmt.Errorf("embedding model is required when algorithm is semantic")
		}
		if r.Embedding.Credentials.HeaderName == "" {
			return fmt.Errorf("embedding credentials header_name is required when algorithm is semantic")
		}
		if r.Embedding.Credentials.HeaderValue == "" {
			return fmt.Errorf("embedding credentials header_value is required when algorithm is semantic")
		}
	}
	if r.WebhookConfig != nil && r.ProxyConfig != nil {
		return fmt.Errorf("webhook_config and proxy_config cannot coexist, only one can be specified")
	}
	if r.WebhookConfig != nil {
		if err := r.WebhookConfig.Validate(); err != nil {
			return fmt.Errorf("webhook_config validation failed: %w", err)
		}
	}
	if r.ProxyConfig != nil {
		if r.ProxyConfig.Host == "" {
			return fmt.Errorf("proxy_config.host cannot be empty")
		}
		if r.ProxyConfig.Port == "" {
			return fmt.Errorf("proxy_config.port cannot be empty")
		}
		if r.ProxyConfig.Protocol != "" && r.ProxyConfig.Protocol != "http" && r.ProxyConfig.Protocol != "https" {
			return fmt.Errorf("proxy_config.protocol must be either 'http' or 'https'")
		}

		for i, target := range r.Targets {
			if target.Provider != "" {
				return fmt.Errorf("target %d: when target has provider specified, proxy_config is not allowed", i)
			}
		}

		for i, target := range r.Targets {
			if target.Stream {
				return fmt.Errorf("target %d: when target has stream set to true, proxy_config is not allowed", i)
			}
		}
	}

	return nil
}

func (r *UpstreamRequest) validateProviderOptions(
	targetIndex int,
	target TargetRequest,
	currentTargets int,
) error {
	if target.Provider == factory.ProviderOpenAI {
		if len(target.ProviderOptions) > 0 {
			if len(target.ProviderOptions) != 1 {
				return fmt.Errorf("target %d: openai provider_options can only contain 'api' field", targetIndex)
			}

			apiValue, exists := target.ProviderOptions["api"]
			if !exists {
				return fmt.Errorf("target %d: openai provider_options can only contain 'api' field", targetIndex)
			}

			apiStr, ok := apiValue.(string)
			if !ok {
				return fmt.Errorf("target %d: openai provider_options 'api' field must be a string", targetIndex)
			}

			if apiStr != openai.CompletionsAPI && apiStr != openai.ResponsesAPI {
				return fmt.Errorf("target %d: openai provider_options 'api' field must be 'completions' or 'responses'", targetIndex)
			}

			if apiStr == openai.ResponsesAPI && currentTargets > 1 {
				return fmt.Errorf("cannot perform load balancing: OpenAI Responses API supports only a single target")
			}
		}
	} else if target.Provider != "" {
		if len(target.ProviderOptions) > 0 {
			return fmt.Errorf("target %d: provider_options must be empty for non-openai providers", targetIndex)
		}
	}

	return nil
}

func (r *UpstreamRequest) isValidProvider(provider string) bool {
	return provider == factory.ProviderOpenAI ||
		provider == factory.ProviderGemini ||
		provider == factory.ProviderAnthropic ||
		provider == factory.ProviderBedrock ||
		provider == factory.ProviderAzure
}
