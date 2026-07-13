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

package tooltransform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const PluginName = "tool_definition_transformation"

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
		return nil, fmt.Errorf("tool_definition_transformation: %w", err)
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
	if format == "" {
		return okResult(), nil
	}
	canonical, err := p.registry.DecodeRequestFor(in.Request.Body, adapter.Format(format))
	if err != nil || canonical == nil {
		return okResult(), nil
	}
	if len(canonical.Tools) == 0 && len(cfg.InjectTools) == 0 {
		return okResult(), nil
	}

	ad, err := p.registry.GetAdapter(adapter.Format(format))
	if err != nil {
		return okResult(), nil
	}
	baseline, baselineErr := ad.EncodeRequest(canonical)

	before := toolNames(canonical.Tools)
	changed := applyTransforms(canonical.Tools, cfg.TransformTools)

	tools, outcomes, err := applyInjections(canonical.Tools, cfg.InjectTools, cfg.onConflict())
	if err != nil {
		if pe, ok := appplugins.AsPluginError(err); ok {
			setExtras(in.Event, rejectData(string(policy.StagePreRequest), reservedName(pe)))
		}
		return nil, err
	}
	canonical.Tools = tools

	if changed || len(outcomes) > 0 {
		transformedNames := matchedToolNames(before, cfg.TransformTools)
		setExtras(in.Event, data(string(policy.StagePreRequest), transformedNames, outcomes))
	}

	if !changed && !injectionChanged(outcomes) {
		return okResult(), nil
	}

	return p.encodeAndGraft(ad, in.Request.Body, baseline, baselineErr, canonical)
}

func (p *Plugin) encodeAndGraft(
	ad adapter.ProviderAdapter,
	originalBody, baseline []byte,
	baselineErr error,
	mutated *adapter.CanonicalRequest,
) (*appplugins.Result, error) {
	encoded, err := ad.EncodeRequest(mutated)
	if err != nil {
		return nil, fmt.Errorf("tool_definition_transformation: graft: %w", err)
	}
	if baselineErr != nil {
		return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: encoded}, nil
	}
	body, err := graftChangedFields(originalBody, baseline, encoded)
	if err != nil {
		body = encoded
	}
	return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: body}, nil
}

func injectionChanged(outcomes []injectOutcome) bool {
	for i := range outcomes {
		if outcomes[i].Outcome == outcomeAppended || outcomes[i].Outcome == outcomeReplaced {
			return true
		}
	}
	return false
}

func toolNames(tools []adapter.CanonicalTool) []string {
	out := make([]string, 0, len(tools))
	for i := range tools {
		out = append(out, tools[i].Name)
	}
	return out
}

func matchedToolNames(before []string, entries []transformDef) []string {
	if len(entries) == 0 {
		return nil
	}
	var out []string
	for _, name := range before {
		for j := range entries {
			if matchToolPattern(entries[j].Tool, name) {
				out = append(out, name)
				break
			}
		}
	}
	return out
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

func graftChangedFields(original, fullEncoded, strippedEncoded []byte) ([]byte, error) {
	var orig, full, stripped map[string]json.RawMessage
	if err := json.Unmarshal(original, &orig); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(fullEncoded, &full); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(strippedEncoded, &stripped); err != nil {
		return nil, err
	}
	for key, fullValue := range full {
		strippedValue, ok := stripped[key]
		if !ok {
			delete(orig, key)
			continue
		}
		if !bytes.Equal(fullValue, strippedValue) {
			orig[key] = strippedValue
		}
	}
	for key, strippedValue := range stripped {
		if _, ok := full[key]; !ok {
			orig[key] = strippedValue
		}
	}
	return json.Marshal(orig)
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
