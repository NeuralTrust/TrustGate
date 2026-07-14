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

package regexreplace

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

var _ appplugins.Plugin = (*Plugin)(nil)

type Plugin struct {
	registry *adapter.Registry
	logger   *slog.Logger
}

func New(registry *adapter.Registry, logger *slog.Logger) *Plugin {
	return &Plugin{registry: registry, logger: logger}
}

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePreResponse}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve}
}

func (p *Plugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM}
}

func (p *Plugin) MutatesRequestBody() bool { return true }

func (p *Plugin) MutatesResponseBody() bool { return true }

func (p *Plugin) MutatesMetadata() bool { return false }

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	if _, err := parseConfig(settings); err != nil {
		return fmt.Errorf("regex_replace: %w", err)
	}
	return nil
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("regex_replace: %w", err)
	}
	switch in.Stage {
	case policy.StagePreRequest:
		if !cfg.isRequestLeg() {
			return passThrough(), nil
		}
		return p.executeRequest(ctx, in, cfg)
	case policy.StagePreResponse:
		if !cfg.isResponseLeg() {
			return passThrough(), nil
		}
		return p.executeResponse(ctx, in, cfg)
	default:
		return passThrough(), nil
	}
}

func (p *Plugin) executeRequest(ctx context.Context, in appplugins.ExecInput, cfg Settings) (*appplugins.Result, error) {
	if in.Request == nil || len(in.Request.Body) == 0 || in.Request.Provider == "" || p.registry == nil {
		return passThrough(), nil
	}
	format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)
	if err != nil {
		p.debug(ctx, "resolve request format failed", slog.Any("error", err))
		return passThrough(), nil
	}
	creq, err := p.registry.DecodeRequestFor(in.Request.Body, format)
	if err != nil || creq == nil {
		p.debug(ctx, "decode request failed", slog.Any("error", err))
		return passThrough(), nil
	}
	body, changed, err := rewriteRequest(p.registry, format, creq, cfg.compiled)
	if err != nil {
		p.debug(ctx, "rewrite request failed", slog.Any("error", err))
		return passThrough(), nil
	}
	return p.decide(in, cfg, changed, body, false), nil
}

func (p *Plugin) executeResponse(ctx context.Context, in appplugins.ExecInput, cfg Settings) (*appplugins.Result, error) {
	if in.Request == nil || in.Response == nil || p.registry == nil {
		return passThrough(), nil
	}
	if in.Request.Provider == "" || len(in.Response.Body) == 0 {
		return passThrough(), nil
	}
	if in.Response.Streaming {
		return passThrough(), nil
	}
	format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)
	if err != nil {
		p.debug(ctx, "resolve response format failed", slog.Any("error", err))
		return passThrough(), nil
	}
	cresp, err := p.registry.DecodeResponseFor(in.Response.Body, format)
	if err != nil || cresp == nil {
		p.debug(ctx, "decode response failed", slog.Any("error", err))
		return passThrough(), nil
	}
	body, changed, err := rewriteResponse(p.registry, format, cresp, cfg.compiled)
	if err != nil {
		p.debug(ctx, "rewrite response failed", slog.Any("error", err))
		return passThrough(), nil
	}
	return p.decide(in, cfg, changed, body, true), nil
}

func (p *Plugin) decide(in appplugins.ExecInput, cfg Settings, changed bool, body []byte, isResponse bool) *appplugins.Result {
	data := &Data{
		Target:  cfg.Target,
		Stage:   string(in.Stage),
		Mode:    string(in.Mode),
		Changed: changed,
	}
	if !changed {
		data.Decision = decisionNoMatch
		setExtras(in.Event, data)
		return passThrough()
	}
	if !appplugins.Blocks(in.Mode) {
		data.Decision = decisionObserved
		setExtras(in.Event, data)
		return passThrough()
	}
	data.Decision = decisionRewritten
	setExtras(in.Event, data)
	appplugins.SetDecisionFromOutcome(in.Event, decisionRewritten)
	if isResponse {
		return &appplugins.Result{StatusCode: http.StatusOK, Body: body, StopUpstream: true}
	}
	return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: body}
}

func (p *Plugin) debug(ctx context.Context, msg string, attrs ...any) {
	if p.logger == nil {
		return
	}
	p.logger.DebugContext(ctx, msg, attrs...)
}

func passThrough() *appplugins.Result {
	return &appplugins.Result{StatusCode: http.StatusOK}
}
