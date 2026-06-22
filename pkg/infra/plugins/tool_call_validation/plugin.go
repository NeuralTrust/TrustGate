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

package tool_call_validation

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const PluginName = "tool_call_validation"

var _ appplugins.Plugin = (*Plugin)(nil)

type Plugin struct {
	registry *adapter.Registry
	llm      providers.Client
	logger   *slog.Logger
}

func New(registry *adapter.Registry, llm providers.Client, logger *slog.Logger) *Plugin {
	return &Plugin{registry: registry, llm: llm, logger: logger}
}

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreResponse}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreResponse}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve}
}

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("tool_call_validation: %w", err)
	}

	if in.Request == nil || in.Response == nil {
		return passThrough(), nil
	}
	if len(in.Request.Body) == 0 || len(in.Response.Body) == 0 {
		return passThrough(), nil
	}
	if in.Response.Streaming {
		return passThrough(), nil
	}
	if in.Request.Provider == "" || p.registry == nil {
		return passThrough(), nil
	}

	format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)
	if err != nil {
		return passThrough(), nil
	}

	creq, err := p.registry.DecodeRequestFor(in.Request.Body, format)
	if err != nil || creq == nil || len(creq.Tools) == 0 {
		return passThrough(), nil
	}

	cresp, err := p.registry.DecodeResponseFor(in.Response.Body, format)
	if err != nil || cresp == nil || len(cresp.ToolCalls) == 0 {
		return passThrough(), nil
	}

	outcome := runRules(ctx, buildEvalContext(cfg, creq, cresp, p.llm), in.Mode, cresp.ToolCalls)
	if !outcome.matched {
		setExtras(in.Event, ToolCallValidationData{Action: actionAllow})
		return passThrough(), nil
	}

	if outcome.rejection != nil {
		setExtras(in.Event, outcome.extras)
		return nil, outcome.rejection
	}

	if outcome.redacted {
		patched, changed := applyRedactions(in.Response.Body, format, outcome.redactions)
		extras := outcome.extras
		if !changed {
			extras.Degraded = true
			if redactSupportsFormat(format) {
				extras.DegradedReason = degradedReasonRedactFailed
			} else {
				extras.DegradedReason = degradedReasonUnsupportedFormat
			}
			setExtras(in.Event, extras)
			return passThrough(), nil
		}
		setExtras(in.Event, extras)
		return &appplugins.Result{StatusCode: http.StatusOK, Body: patched, StopUpstream: true}, nil
	}

	setExtras(in.Event, outcome.extras)
	appplugins.SetDecision(in.Event, in.Mode)
	return passThrough(), nil
}

func passThrough() *appplugins.Result {
	return &appplugins.Result{StatusCode: http.StatusOK}
}
