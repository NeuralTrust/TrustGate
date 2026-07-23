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

package openaimoderation

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

const (
	inputTypeText = "text"

	decisionBlock       = "block"
	decisionReported    = "reported"
	decisionAllowed     = "allowed"
	decisionFailedOpen  = "failed_open"
	decisionUnavailable = "unavailable"
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
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePreResponse}
}

func (p *Plugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM}
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
		return nil, fmt.Errorf("openai_moderation: %w", err)
	}

	if !cfg.selectsStage(in.Stage) {
		return passThrough(), nil
	}

	if p.baseURL == "" {
		p.warn(ctx, "openai moderation base url not configured",
			slog.String("plugin", PluginName),
			slog.String("stage", string(in.Stage)),
		)
		return passThrough(), nil
	}

	if in.Request == nil || p.registry == nil || in.Request.Provider == "" {
		return passThrough(), nil
	}

	format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)
	if err != nil {
		return passThrough(), nil
	}

	text := p.extractText(in, format)
	if strings.TrimSpace(text) == "" {
		return passThrough(), nil
	}

	req := moderationRequest{
		Model: cfg.Model,
		Input: []moderationInput{{Type: inputTypeText, Text: text}},
	}

	resp, err := p.client.Moderate(ctx, p.baseURL, cfg.APIKey, req)
	if err != nil {
		p.warn(ctx, "openai moderation call failed",
			slog.String("plugin", PluginName),
			slog.String("stage", string(in.Stage)),
			slog.Any("error", err),
		)
		if appplugins.Blocks(in.Mode) {
			setExtras(in.Event, ModerationData{Model: cfg.Model, Decision: decisionUnavailable})
			return nil, unavailableError()
		}
		setExtras(in.Event, ModerationData{Model: cfg.Model, Decision: decisionFailedOpen})
		appplugins.SetDecisionFromOutcome(in.Event, decisionFailedOpen)
		return passThrough(), nil
	}

	agg := aggregate(resp.Results)
	violations := evaluate(cfg, agg)
	topCategory, topScore := maxScore(agg)

	data := ModerationData{
		Model:             cfg.Model,
		CategoryScores:    agg.scores,
		MaxScore:          topScore,
		MaxScoreCategory:  topCategory,
		FlaggedByOpenAI:   agg.anyFlagged,
		FlaggedCategories: violations,
	}

	if len(violations) > 0 && appplugins.Blocks(in.Mode) {
		data.Decision = decisionBlock
		setExtras(in.Event, data)
		recordScore(in.Event, data)
		appplugins.SetDecisionFromOutcome(in.Event, decisionBlock)
		return nil, blockError(cfg.Action.Message, violations)
	}

	if len(violations) > 0 {
		data.Decision = decisionReported
	} else {
		data.Decision = decisionAllowed
	}
	setExtras(in.Event, data)
	if len(violations) > 0 {
		recordScore(in.Event, data)
	}
	appplugins.SetDecisionFromOutcome(in.Event, data.Decision)
	return passThrough(), nil
}

func (p *Plugin) extractText(in appplugins.ExecInput, format adapter.Format) string {
	if in.Stage == policy.StagePreResponse {
		if in.Response == nil || in.Response.Streaming || len(in.Response.Body) == 0 {
			return ""
		}
		cresp, err := p.registry.DecodeResponseFor(in.Response.Body, format)
		if err != nil || cresp == nil {
			return ""
		}
		return responseText(cresp)
	}
	if len(in.Request.Body) == 0 {
		return ""
	}
	creq, err := p.registry.DecodeRequestFor(in.Request.Body, format)
	if err != nil || creq == nil {
		return ""
	}
	return joinRequestText(creq)
}

func (p *Plugin) warn(ctx context.Context, msg string, attrs ...any) {
	if p.logger == nil {
		return
	}
	p.logger.WarnContext(ctx, msg, attrs...)
}

func passThrough() *appplugins.Result {
	return &appplugins.Result{StatusCode: http.StatusOK}
}
