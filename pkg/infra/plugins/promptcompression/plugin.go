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

// Package promptcompression shrinks the request prompt before it reaches the
// model: standalone and fenced JSON is minified, ANSI escape sequences are
// stripped, and redundant whitespace is collapsed. All transforms are
// deterministic, so repeated turns re-compress history to identical bytes and
// provider prompt-cache prefixes remain stable. The plugin always fails open:
// any decode, transform, or encode problem passes the original request
// through untouched.
package promptcompression

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
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve}
}

func (p *Plugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM}
}

func (p *Plugin) MutatesRequestBody() bool { return true }

func (p *Plugin) MutatesResponseBody() bool { return false }

func (p *Plugin) MutatesMetadata() bool { return false }

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	if _, err := parseConfig(settings); err != nil {
		return fmt.Errorf("prompt_compression: %w", err)
	}
	return nil
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("prompt_compression: %w", err)
	}
	if in.Stage != policy.StagePreRequest {
		return passThrough(), nil
	}
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
	body, changed, saved, err := rewriteRequest(p.registry, format, creq, cfg)
	if err != nil {
		p.debug(ctx, "rewrite request failed", slog.Any("error", err))
		return passThrough(), nil
	}
	return p.decide(in, cfg, changed, saved, body), nil
}

func (p *Plugin) decide(in appplugins.ExecInput, cfg Settings, changed bool, saved int, body []byte) *appplugins.Result {
	bytesIn := len(in.Request.Body)
	data := &Data{
		Stage:      string(in.Stage),
		Mode:       string(in.Mode),
		Transforms: cfg.describe(),
		BytesIn:    bytesIn,
	}
	if !changed {
		data.Decision = decisionNoChange
		data.BytesOut = bytesIn
		setExtras(in.Event, data)
		return passThrough()
	}
	data.BytesOut = len(body)
	data.BytesSaved = saved
	if bytesIn > 0 {
		data.Ratio = float64(len(body)) / float64(bytesIn)
	}
	if !appplugins.Blocks(in.Mode) {
		data.Decision = decisionObserved
		setExtras(in.Event, data)
		return passThrough()
	}
	// Fail open when the re-encoded body somehow grew: forwarding the original
	// is always safe, and a "compression" that inflates the request would both
	// waste tokens and churn provider caches.
	if len(body) >= bytesIn {
		data.Decision = decisionNoChange
		data.BytesOut = bytesIn
		data.BytesSaved = 0
		data.Ratio = 0
		setExtras(in.Event, data)
		return passThrough()
	}
	data.Decision = decisionCompressed
	setExtras(in.Event, data)
	appplugins.SetDecisionFromOutcome(in.Event, decisionCompressed)
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
