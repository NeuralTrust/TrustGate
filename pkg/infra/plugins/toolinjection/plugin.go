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

package toolinjection

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const PluginName = "tool_injection"

var _ appplugins.Plugin = (*Plugin)(nil)

type Plugin struct {
	registry *adapter.Registry
}

func New(registry *adapter.Registry) *Plugin {
	return &Plugin{registry: registry}
}

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MutatesRequestBody() bool { return true }

func (p *Plugin) MutatesResponseBody() bool { return false }

func (p *Plugin) MutatesMetadata() bool { return false }

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce}
}

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(_ context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	if p.registry == nil {
		return okResult(), nil
	}
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("tool_injection: %w", err)
	}
	switch in.Stage {
	case policy.StagePreRequest:
		return p.preRequest(cfg, in)
	default:
		return okResult(), nil
	}
}

func (p *Plugin) preRequest(cfg *config, in appplugins.ExecInput) (*appplugins.Result, error) {
	if in.Request == nil || len(in.Request.Body) == 0 {
		return okResult(), nil
	}
	format := wireFormat(in.Request)
	if format == "" || !adapter.IsChatRequest(in.Request.ProxyCapability, adapter.Format(format)) {
		return okResult(), nil
	}
	canonical, err := p.registry.DecodeRequestFor(in.Request.Body, adapter.Format(format))
	if adapter.IsRequestDecodeError(err) {
		return nil, appplugins.UndecodableRequestError(PluginName)
	}
	if err != nil || canonical == nil {
		return okResult(), nil
	}

	ad, err := p.registry.GetAdapter(adapter.Format(format))
	if err != nil {
		return okResult(), nil
	}
	baseline := canonical.Clone()

	entries, dropLegacy, skipped, err := resolveLegacyConflicts(cfg.InjectTools, legacyFunctions(ad, in.Request.Body, canonical), cfg.onConflict())
	if err != nil {
		return nil, rejected(in, err)
	}
	tools, outcomes, err := applyInjections(canonical.Tools, entries, cfg.onConflict())
	if err != nil {
		return nil, rejected(in, err)
	}
	canonical.Tools = tools
	for i := range outcomes {
		if dropLegacy[outcomes[i].Name] {
			outcomes[i].Outcome = outcomeReplaced
		}
	}
	outcomes = append(outcomes, skipped...)

	if len(outcomes) > 0 {
		setExtras(in.Event, data(string(policy.StagePreRequest), outcomes))
	}

	// A body with keys the decoder folds into one is re-encoded even when
	// nothing was injected: the conflicts were judged on the tools decoded,
	// which the upstream may not read.
	if !injectionChanged(outcomes) && !adapter.HasAmbiguousKeys(in.Request.Body) {
		return okResult(), nil
	}

	body, err := adapter.GraftChangedFieldsWith(ad, in.Request.Body, baseline, canonical, adapter.GraftOptions{
		KeepUnmodelledTool: func(u adapter.UnmodelledTool) bool {
			return u.Kind != adapter.LegacyFunctionKind || !dropLegacy[u.Name]
		},
	})
	if err != nil {
		return nil, fmt.Errorf("tool_injection: graft: %w", err)
	}
	return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: body}, nil
}

func rejected(in appplugins.ExecInput, err error) error {
	if pe, ok := appplugins.AsPluginError(err); ok {
		setExtras(in.Event, rejectData(string(policy.StagePreRequest), reservedName(pe)))
	}
	return err
}

// legacyFunctions returns the names of the legacy Chat functions body
// declares, which canonical does not model.
func legacyFunctions(ad adapter.RequestAdapter, body []byte, canonical *adapter.CanonicalRequest) map[string]bool {
	unmodelled, _ := adapter.UnmodelledTools(ad, body, canonical)
	var out map[string]bool
	for _, u := range unmodelled {
		if u.Kind == adapter.LegacyFunctionKind && u.Name != "" {
			if out == nil {
				out = map[string]bool{}
			}
			out[u.Name] = true
		}
	}
	return out
}

func injectionChanged(outcomes []injectOutcome) bool {
	for i := range outcomes {
		if outcomes[i].Outcome == outcomeAppended || outcomes[i].Outcome == outcomeReplaced {
			return true
		}
	}
	return false
}

func reservedName(pe *appplugins.PluginError) string {
	if pe == nil || len(pe.Body) == 0 {
		return ""
	}
	var decoded struct {
		Error struct {
			Name string `json:"name"`
		} `json:"error"`
	}
	if err := json.Unmarshal(pe.Body, &decoded); err != nil {
		return ""
	}
	return decoded.Error.Name
}

func wireFormat(req *infracontext.RequestContext) string {
	if req == nil {
		return ""
	}
	if req.SourceFormat != "" {
		return req.SourceFormat
	}
	return req.Provider
}

func okResult() *appplugins.Result {
	return &appplugins.Result{StatusCode: http.StatusOK}
}
