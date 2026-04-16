package upstream

import (
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/google/uuid"
)

type CreateParams struct {
	GatewayID       uuid.UUID
	Name            string
	Algorithm       string
	Targets         []Target
	EmbeddingConfig *EmbeddingConfig
	HealthChecks    *HealthCheck
	Websocket       *WebsocketConfig
	Proxy           *Proxy
	Tags            domain.TagsJSON
}

func New(params CreateParams) (*Upstream, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID: %w", err)
	}
	now := time.Now()
	return &Upstream{
		ID:              id,
		GatewayID:       params.GatewayID,
		Name:            params.Name,
		Algorithm:       params.Algorithm,
		Targets:         params.Targets,
		EmbeddingConfig: params.EmbeddingConfig,
		HealthChecks:    params.HealthChecks,
		Websocket:       params.Websocket,
		Proxy:           params.Proxy,
		Tags:            params.Tags,
		CreatedAt:       now,
		UpdatedAt:       now,
	}, nil
}

func NewProxy(host, port, protocol string) *Proxy {
	if protocol == "" {
		protocol = "http"
	}
	return &Proxy{
		Host:     host,
		Port:     port,
		Protocol: protocol,
	}
}

func NewEmbeddingConfig(provider, model string, credentials domain.CredentialsJSON) *EmbeddingConfig {
	return &EmbeddingConfig{
		Provider:    provider,
		Model:       model,
		Credentials: credentials,
	}
}

func NewHealthCheck(passive bool, path string, headers domain.HeadersJSON, threshold, interval int) *HealthCheck {
	return &HealthCheck{
		Passive:   passive,
		Path:      path,
		Headers:   headers,
		Threshold: threshold,
		Interval:  interval,
	}
}

func NewWebsocketConfig(
	enableDirectComm, returnErrorDetails bool,
	pingPeriod, pongWait, handshakeTimeout string,
	readBuf, writeBuf int,
) *WebsocketConfig {
	return &WebsocketConfig{
		EnableDirectCommunication: enableDirectComm,
		ReturnErrorDetails:        returnErrorDetails,
		PingPeriod:                pingPeriod,
		PongWait:                  pongWait,
		HandshakeTimeout:          handshakeTimeout,
		ReadBufferSize:            readBuf,
		WriteBufferSize:           writeBuf,
	}
}

func NewTarget(
	id string,
	weight int,
	tags domain.TagsJSON,
	headers domain.HeadersJSON,
	path, host string,
	port int,
	protocol, provider string,
	providerOptions map[string]any,
	models ModelsJSON,
	defaultModel, description string,
	stream, insecureSSL bool,
	credentials domain.CredentialsJSON,
) Target {
	return Target{
		ID:              id,
		Weight:          weight,
		Tags:            tags,
		Headers:         headers,
		Path:            path,
		Host:            host,
		Port:            port,
		Protocol:        protocol,
		Provider:        provider,
		ProviderOptions: providerOptions,
		Models:          models,
		DefaultModel:    defaultModel,
		Description:     description,
		Stream:          stream,
		InsecureSSL:     insecureSSL,
		Credentials:     credentials,
	}
}

func NewOAuth2Auth(config *TargetOAuthConfig) *TargetAuth {
	return &TargetAuth{
		Type:  AuthTypeOAuth2,
		OAuth: config,
	}
}

func NewGCPServiceAccountAuth(encryptedSA string) *TargetAuth {
	return &TargetAuth{
		Type:              AuthTypeGCPServiceAccount,
		GCPServiceAccount: &encryptedSA,
	}
}
