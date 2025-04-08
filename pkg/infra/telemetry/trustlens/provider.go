package trustlens

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/NeuralTrust/TrustGate/pkg/utils"
	"github.com/google/uuid"
)

const (
	ProviderName = "trustlens"
)

type Config struct {
	Url   string `mapstructure:"url"`
	Token string `mapstructure:"token"`
}

type TraceRequest struct {
	TraceId        string `json:"trace_id"`
	InteractionId  string `json:"interaction_id"`
	ConversationId string `json:"conversation_id"`
	Input          string `json:"input"`
	Output         string `json:"output"`
	Task           string `json:"task"`
	StartTime      int64  `json:"start_timestamp"`
	EndTime        int64  `json:"end_timestamp"`
	Locale         string `json:"locale"`
	Device         string `json:"device"`
	Os             string `json:"os"`
	Browser        string `json:"browser"`
}

type Provider struct {
	cfg     Config
	breaker httpx.CircuitBreaker
	client  httpx.Client
}

func NewTrustLensProvider(cfg Config, breaker httpx.CircuitBreaker, client httpx.Client) *Provider {
	return &Provider{
		cfg:     cfg,
		breaker: breaker,
		client:  client,
	}
}

func (p *Provider) Name() string {
	return ProviderName
}

func (p *Provider) ValidateConfig() error {
	if p.cfg.Url == "" {
		return errors.New("trustlens url is required")
	}
	if p.cfg.Token == "" {
		return errors.New("trustlens token is required")
	}
	return nil
}

func (p *Provider) Handle(ctx context.Context, req *types.RequestContext, resp *types.ResponseContext) error {
	if req.Method == http.MethodGet {
		return nil
	}

	traceReq, err := p.buildTraceRequest(req, resp)
	if err != nil {
		return fmt.Errorf("failed to build trace request: %w", err)
	}

	requestBody, err := json.Marshal(traceReq)
	if err != nil {
		return fmt.Errorf("failed to marshal trace request: %w", err)
	}

	err = p.breaker.Execute(func() error {
		httpReq, err := p.buildHttpRequest(ctx, requestBody)
		if err != nil {
			return fmt.Errorf("failed to create HTTP request: %w", err)
		}

		res, err := p.client.Do(httpReq)
		if err != nil {
			return fmt.Errorf("trustlens request failed: %w", err)
		}
		defer res.Body.Close()

		if _, err := io.ReadAll(res.Body); err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}

		if res.StatusCode >= http.StatusBadRequest {
			return fmt.Errorf("trustlens returned status code %d", res.StatusCode)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("trustlens call failed: %w", err)
	}

	return nil
}

func (p *Provider) buildTraceRequest(
	req *types.RequestContext,
	resp *types.ResponseContext,
) (*TraceRequest, error) {
	trace := &TraceRequest{
		TraceId:        req.GatewayID,
		InteractionId:  uuid.New().String(),
		ConversationId: uuid.New().String(),
		Input:          string(req.Body),
		Output:         string(resp.Body),
		Task:           "message",
		StartTime:      req.ProcessAt.UnixMilli(),
		EndTime:        resp.ProcessAt.UnixMilli(),
	}
	userAgentInfo, ok := req.Metadata["user_agent_info"].(*utils.UserAgentInfo)
	if !ok {
		return nil, errors.New("user_agent_info not found in request metadata")
	}
	if userAgentInfo != nil {
		trace.Locale = userAgentInfo.Locale
		trace.Device = userAgentInfo.Device
		trace.Os = userAgentInfo.OS
		trace.Browser = userAgentInfo.Browser
	}
	return trace, nil
}

func (p *Provider) buildHttpRequest(ctx context.Context, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.Url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", p.cfg.Token))
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}
