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

package toolallowlist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"unicode"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const PluginName = "tool_allowlist"

var _ appplugins.Plugin = (*Plugin)(nil)

var errNullBody = errors.New("tool_allowlist: request body is null")

var ownedToolKeys = []string{"tools", "tool_choice", "parallel_tool_calls", "toolConfig"}

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
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve}
}

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(_ context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("tool_allowlist: %w", err)
	}
	if p.registry == nil || in.Request == nil || len(in.Request.Body) == 0 {
		return okResult(), nil
	}
	format := wireFormat(in.Request)
	if format == "" {
		return okResult(), nil
	}
	scan := scanToolKeys(in.Request.Body)
	canonical, err := p.registry.DecodeRequestFor(in.Request.Body, adapter.Format(format))
	if appplugins.Blocks(in.Mode) && (scan.ambiguous || (err != nil && scan.present)) {
		setExtras(in.Event, ToolAllowlistData{
			Provider:       in.Request.Provider,
			ToolsRequested: []string{},
			ToolsAllowed:   []string{},
			ToolsRemoved:   []string{},
			Action:         actionRejected,
			Decision:       appplugins.DecisionForMode(in.Mode),
		})
		return newRejectResult(http.StatusBadRequest, errInvalidToolsField, nil)
	}
	if err != nil || canonical == nil || len(canonical.Tools) == 0 {
		return okResult(), nil
	}

	requested := toolNames(canonical.Tools)
	kept, removed, keptCount, removedCount := filter(canonical.Tools, cfg)
	data := ToolAllowlistData{
		Provider:       in.Request.Provider,
		ToolsRequested: requested,
		ToolsAllowed:   kept,
		ToolsRemoved:   removed,
		OnEmpty:        cfg.OnEmptyAfterFilter,
		Decision:       appplugins.DecisionForMode(in.Mode),
	}

	if removedCount == 0 {
		data.Action = actionSkipped
		setExtras(in.Event, data)
		return okResult(), nil
	}

	data.Action = plannedAction(keptCount, cfg)
	setExtras(in.Event, data)

	if !appplugins.Blocks(in.Mode) {
		appplugins.SetDecision(in.Event, in.Mode)
		return okResult(), nil
	}

	if keptCount > 0 {
		return p.stripTools(in.Request.Body, format, canonical, cfg)
	}

	switch cfg.OnEmptyAfterFilter {
	case onEmptyStripField:
		return rewriteEmpty(in.Request.Body, true)
	case onEmptyPassThrough:
		return rewriteEmpty(in.Request.Body, false)
	default:
		return newRejectResult(http.StatusForbidden, errNoToolsAllowed, requested)
	}
}

type toolKeyScan struct {
	present   bool
	ambiguous bool
}

func scanToolKeys(body []byte) toolKeyScan {
	var scan toolKeyScan
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return scan
	}
	seen := make(map[string]int, len(ownedToolKeys))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return scan
		}
		key, ok := tok.(string)
		if !ok {
			return scan
		}
		if canonical, owned := ownedToolKey(key); owned {
			scan.present = true
			seen[canonical]++
			if key != canonical || seen[canonical] > 1 {
				scan.ambiguous = true
			}
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return scan
		}
	}
	return scan
}

func ownedToolKey(key string) (string, bool) {
	for _, owned := range ownedToolKeys {
		if strings.EqualFold(key, owned) {
			return owned, true
		}
	}
	return "", false
}

func (p *Plugin) stripTools(
	originalBody []byte,
	format string,
	canonical *adapter.CanonicalRequest,
	cfg *config,
) (*appplugins.Result, error) {
	ad, err := p.registry.GetAdapter(adapter.Format(format))
	if err != nil {
		return nil, fmt.Errorf("tool_allowlist: strip: %w", err)
	}
	fullEncoded, err := ad.EncodeRequest(canonical)
	if err != nil {
		return nil, fmt.Errorf("tool_allowlist: strip: %w", err)
	}
	kept := make([]adapter.CanonicalTool, 0, len(canonical.Tools))
	for i := range canonical.Tools {
		if keepTool(canonical.Tools[i].Name, cfg) {
			kept = append(kept, canonical.Tools[i])
		}
	}
	canonical.Tools = kept
	strippedEncoded, err := ad.EncodeRequest(canonical)
	if err != nil {
		return nil, fmt.Errorf("tool_allowlist: strip: %w", err)
	}
	body, err := graftChangedFields(originalBody, fullEncoded, strippedEncoded)
	if err != nil {
		body = strippedEncoded
	}
	return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: body}, nil
}

func rewriteEmpty(originalBody []byte, deleteTools bool) (*appplugins.Result, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(originalBody, &m); err != nil {
		return nil, fmt.Errorf("tool_allowlist: rewrite: %w", err)
	}
	for key := range m {
		canonical, owned := ownedToolKey(key)
		if owned && (canonical != "tools" || deleteTools) {
			delete(m, key)
		}
	}
	if !deleteTools {
		m["tools"] = json.RawMessage("[]")
	}
	body, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("tool_allowlist: rewrite: %w", err)
	}
	return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: body}, nil
}

func newRejectResult(status int, kind string, requested []string) (*appplugins.Result, error) {
	body, err := json.Marshal(newErrorBody(kind, requested))
	if err != nil {
		return nil, &appplugins.PluginError{
			StatusCode: status,
			Message:    kind,
		}
	}
	return &appplugins.Result{
		StopUpstream: true,
		StatusCode:   status,
		Headers:      map[string][]string{"Content-Type": {"application/json"}},
		Body:         body,
	}, nil
}

func keepTool(name string, cfg *config) bool {
	if !printableName(name) {
		return false
	}
	if len(cfg.AllowTools) > 0 {
		if _, ok := matchAny(cfg.AllowTools, name); !ok {
			return false
		}
	}
	if _, ok := matchAny(cfg.DenyTools, name); ok {
		return false
	}
	return true
}

func filter(tools []adapter.CanonicalTool, cfg *config) (kept, removed []string, keptCount, removedCount int) {
	kept = make([]string, 0, len(tools))
	removed = make([]string, 0, len(tools))
	for i := range tools {
		name := tools[i].Name
		if keepTool(name, cfg) {
			keptCount++
			if name != "" {
				kept = append(kept, name)
			}
			continue
		}
		removedCount++
		if name != "" {
			removed = append(removed, name)
		}
	}
	return kept, removed, keptCount, removedCount
}

func plannedAction(keptCount int, cfg *config) string {
	if keptCount > 0 {
		return actionStripped
	}
	switch cfg.OnEmptyAfterFilter {
	case onEmptyPassThrough:
		return actionPassThrough
	case onEmptyStripField:
		return actionStripped
	default:
		return actionRejected
	}
}

func toolNames(tools []adapter.CanonicalTool) []string {
	names := make([]string, 0, len(tools))
	for i := range tools {
		if tools[i].Name == "" {
			continue
		}
		names = append(names, tools[i].Name)
	}
	return names
}

func matchAny(patterns []string, name string) (string, bool) {
	for _, p := range patterns {
		if matchToolPattern(p, name) {
			return p, true
		}
	}
	return "", false
}

func printableName(name string) bool {
	return strings.IndexFunc(name, func(r rune) bool { return !unicode.IsPrint(r) }) < 0
}

func matchToolPattern(pattern, name string) bool {
	const sentinel = "\x00"
	p := strings.ReplaceAll(pattern, "/", sentinel)
	n := strings.ReplaceAll(name, "/", sentinel)
	ok, err := path.Match(p, n)
	return err == nil && ok
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
	if orig == nil {
		return nil, errNullBody
	}
	touched := make(map[string]struct{}, len(full))
	for key, fullValue := range full {
		strippedValue, ok := stripped[key]
		if !ok {
			delete(orig, key)
			touched[key] = struct{}{}
			continue
		}
		if !bytes.Equal(fullValue, strippedValue) {
			orig[key] = strippedValue
			touched[key] = struct{}{}
		}
	}
	for key, strippedValue := range stripped {
		if _, ok := full[key]; !ok {
			orig[key] = strippedValue
			touched[key] = struct{}{}
		}
	}
	dropCaseVariants(orig, touched)
	return json.Marshal(orig)
}

func dropCaseVariants(orig map[string]json.RawMessage, touched map[string]struct{}) {
	for key := range orig {
		if _, ok := touched[key]; ok {
			continue
		}
		for owned := range touched {
			if strings.EqualFold(key, owned) {
				delete(orig, key)
				break
			}
		}
	}
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

func okResult() *appplugins.Result { return &appplugins.Result{StatusCode: http.StatusOK} }

func setExtras(event *metrics.EventContext, data ToolAllowlistData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
}
