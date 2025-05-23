package response

import (
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
)

type ListRulesOutput struct {
	Gateway GatewayOutput          `json:"gateway"`
	Rules   []ForwardingRuleOutput `json:"rules"`
}

type GatewayOutput struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Status          string                 `json:"status"`
	RequiredPlugins domain.PluginChainJSON `json:"plugin_chain,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

type ForwardingRuleOutput struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Upstream    *UpstreamOutput        `json:"upstream"`
	ServiceID   string                 `json:"service_id"`
	Path        string                 `json:"path"`
	Methods     domain.MethodsJSON     `json:"methods"`
	Headers     domain.HeadersJSON     `json:"headers"`
	PluginChain domain.PluginChainJSON `json:"plugin_chain,omitempty"`
	Active      bool                   `json:"active"`
	TrustLens   *domain.TrustLensJSON  `json:"trustlens"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

type UpstreamOutput struct {
	Name      string           `json:"name"`
	Algorithm string           `json:"algorithm"`
	Targets   upstream.Targets `json:"targets"`
}
