// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package trustguard

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const PluginName = "trustguard"

const (
	directionInput  = "input"
	directionOutput = "output"
	contentTypeJSON = "application/json"
)

const (
	protocolLLM = "llm"
	protocolMCP = "mcp"
	protocolA2A = "a2a"
)

const (
	decisionBlocked    = "blocked"
	decisionReported   = "reported"
	decisionAllowed    = "allowed"
	decisionFailedOpen = "failed_open"
	statusBlock        = "block"
)

var _ appplugins.Plugin = (*Plugin)(nil)

type Plugin struct {
	registry *adapter.Registry
	client   *client
	baseURL  string
	logger   *slog.Logger
}

func New(registry *adapter.Registry, baseURL string, timeout time.Duration, logger *slog.Logger) *Plugin {
	return &Plugin{
		registry: registry,
		client:   newClient(timeout),
		baseURL:  baseURL,
		logger:   logger,
	}
}

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePreResponse}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePreResponse}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve}
}

func (p *Plugin) MutatesRequestBody() bool { return false }

func (p *Plugin) MutatesResponseBody() bool { return false }

func (p *Plugin) MutatesMetadata() bool { return false }

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("trustguard: %w", err)
	}

	if !cfg.selectsStage(in.Stage) {
		return passThrough(), nil
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = p.baseURL
	}
	if baseURL == "" {
		p.warn(ctx, "trustguard base url not configured",
			slog.String("plugin", PluginName),
			slog.String("stage", string(in.Stage)),
		)
		return passThrough(), nil
	}

	if in.Request == nil || p.registry == nil || in.Request.Provider == "" {
		return passThrough(), nil
	}

	direction := directionInput
	if in.Stage == policy.StagePreResponse {
		direction = directionOutput
	}

	format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)
	if err != nil {
		return passThrough(), nil
	}

	var text string
	if direction == directionInput {
		if len(in.Request.Body) == 0 {
			return passThrough(), nil
		}
		creq, decErr := p.registry.DecodeRequestFor(in.Request.Body, format)
		if decErr != nil || creq == nil {
			return passThrough(), nil
		}
		text = joinRequestText(creq)
	} else {
		if in.Response == nil || in.Response.Streaming || len(in.Response.Body) == 0 {
			return passThrough(), nil
		}
		cresp, decErr := p.registry.DecodeResponseFor(in.Response.Body, format)
		if decErr != nil || cresp == nil {
			return passThrough(), nil
		}
		text = cresp.Content
	}
	if strings.TrimSpace(text) == "" {
		return passThrough(), nil
	}

	body := GuardRequest{
		Input:      GuardInput{Input: text},
		Direction:  direction,
		Protocol:   protocolFor(in.Request.ConsumerType),
		SessionID:  in.Request.SessionID,
		ConsumerID: in.Request.ConsumerID,
		Attributes: GuardAttributes{
			ContentType: contentTypeJSON,
			Model: GuardModel{
				Name:     in.Request.RequestedModel,
				Provider: in.Request.Provider,
			},
		},
	}

	resp, err := p.client.Guard(ctx, baseURL, cfg.APIKey, body)
	if err != nil {
		p.warn(ctx, "trustguard call failed, failing open",
			slog.String("plugin", PluginName),
			slog.String("stage", string(in.Stage)),
			slog.String("direction", direction),
			slog.Any("error", err),
		)
		setExtras(in.Event, guardData{Direction: direction, Decision: decisionFailedOpen, FailedOpen: true})
		return passThrough(), nil
	}

	data := guardData{
		Direction:     direction,
		Status:        resp.Status,
		TraceID:       resp.TraceID,
		RequestID:     resp.RequestID,
		FindingsCount: len(resp.Findings),
	}

	if resp.Status == statusBlock && appplugins.Blocks(in.Mode) {
		data.Decision = decisionBlocked
		setExtras(in.Event, data)
		return nil, blockError(resp)
	}

	if resp.Status == statusBlock {
		data.Decision = decisionReported
	} else {
		data.Decision = decisionAllowed
	}
	setExtras(in.Event, data)
	appplugins.SetDecision(in.Event, in.Mode)
	return passThrough(), nil
}

func (p *Plugin) warn(ctx context.Context, msg string, attrs ...any) {
	if p.logger == nil {
		return
	}
	p.logger.WarnContext(ctx, msg, attrs...)
}

func protocolFor(consumerType string) string {
	switch strings.ToLower(strings.TrimSpace(consumerType)) {
	case protocolMCP:
		return protocolMCP
	case protocolA2A:
		return protocolA2A
	default:
		return protocolLLM
	}
}

func joinRequestText(creq *adapter.CanonicalRequest) string {
	parts := make([]string, 0, len(creq.Messages)+1)
	if strings.TrimSpace(creq.System) != "" {
		parts = append(parts, creq.System)
	}
	for _, msg := range creq.Messages {
		if strings.TrimSpace(msg.Content) != "" {
			parts = append(parts, msg.Content)
		}
	}
	return strings.Join(parts, "\n")
}

func passThrough() *appplugins.Result {
	return &appplugins.Result{StatusCode: http.StatusOK}
}
