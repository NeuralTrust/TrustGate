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

package azurecontentsafety

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

const PluginName = "azure_content_safety"

const (
	decisionBlocked      = "blocked"
	decisionReported     = "reported"
	decisionAllowed      = "allowed"
	decisionFailedClosed = "failed_closed"
)

var _ appplugins.Plugin = (*Plugin)(nil)

type Plugin struct {
	registry *adapter.Registry
	client   *client
	logger   *slog.Logger
}

func New(registry *adapter.Registry, logger *slog.Logger) *Plugin {
	return &Plugin{
		registry: registry,
		client:   newClient(),
		logger:   logger,
	}
}

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
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
		return nil, fmt.Errorf("azure_content_safety: %w", err)
	}

	if in.Stage != policy.StagePreRequest {
		return passThrough(), nil
	}
	if in.Request == nil || p.registry == nil || in.Request.Provider == "" || len(in.Request.Body) == 0 {
		return passThrough(), nil
	}

	format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)
	if err != nil {
		return passThrough(), nil
	}
	creq, decErr := p.registry.DecodeRequestFor(in.Request.Body, format)
	if decErr != nil || creq == nil {
		return passThrough(), nil
	}
	text := joinRequestText(creq)
	if strings.TrimSpace(text) == "" {
		return passThrough(), nil
	}

	start := time.Now()
	resp, err := p.client.Analyze(ctx, cfg.Endpoint, cfg.APIKey, analyzeRequest{
		Text:       text,
		Categories: cfg.Categories,
		OutputType: cfg.OutputType,
	})
	latency := time.Since(start).Milliseconds()
	if err != nil {
		data := &Data{
			Endpoint:   cfg.Endpoint,
			OutputType: cfg.OutputType,
			Mode:       string(in.Mode),
			LatencyMS:  latency,
			FailedOpen: true,
			Decision:   decisionFailedClosed,
		}
		if appplugins.Blocks(in.Mode) {
			p.warn(ctx, "azure content safety call failed, failing closed",
				slog.String("plugin", PluginName),
				slog.String("stage", string(in.Stage)),
				slog.Any("error", err),
			)
			setExtras(in.Event, data)
			return nil, fmt.Errorf("azure_content_safety: analyze: %w", err)
		}
		p.warn(ctx, "azure content safety call failed, observe mode passing through",
			slog.String("plugin", PluginName),
			slog.String("stage", string(in.Stage)),
			slog.Any("error", err),
		)
		setExtras(in.Event, data)
		appplugins.SetDecisionFromOutcome(in.Event, decisionFailedClosed)
		return passThrough(), nil
	}

	severities, breaches := evaluate(resp, cfg)
	data := &Data{
		Endpoint:   cfg.Endpoint,
		OutputType: cfg.OutputType,
		Severities: severities,
		Mode:       string(in.Mode),
		LatencyMS:  latency,
	}

	if len(breaches) > 0 && appplugins.Blocks(in.Mode) {
		data.Decision = decisionBlocked
		data.Breached = breachedNames(breaches)
		setExtras(in.Event, data)
		appplugins.SetDecisionFromOutcome(in.Event, decisionBlocked)
		return nil, blockError(cfg.Message, breaches)
	}

	if len(breaches) > 0 {
		data.Decision = decisionReported
		data.Breached = breachedNames(breaches)
	} else {
		data.Decision = decisionAllowed
	}
	setExtras(in.Event, data)
	appplugins.SetDecisionFromOutcome(in.Event, data.Decision)
	return passThrough(), nil
}

func (p *Plugin) warn(ctx context.Context, msg string, attrs ...any) {
	if p.logger == nil {
		return
	}
	p.logger.WarnContext(ctx, msg, attrs...)
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

func evaluate(resp *analyzeResponse, cfg Settings) (map[string]int, []breachedCategory) {
	if resp == nil {
		return nil, nil
	}
	severities := make(map[string]int, len(resp.CategoriesAnalysis))
	var breaches []breachedCategory
	for _, analysis := range resp.CategoriesAnalysis {
		severities[analysis.Category] = analysis.Severity
		threshold, ok := cfg.CategorySeverity[analysis.Category]
		if !ok {
			continue
		}
		if analysis.Severity >= threshold {
			breaches = append(breaches, breachedCategory{
				Category:  analysis.Category,
				Severity:  analysis.Severity,
				Threshold: threshold,
			})
		}
	}
	return severities, breaches
}

func breachedNames(breaches []breachedCategory) []string {
	names := make([]string, 0, len(breaches))
	for _, breach := range breaches {
		names = append(names, breach.Category)
	}
	return names
}

func passThrough() *appplugins.Result {
	return &appplugins.Result{StatusCode: http.StatusOK}
}
