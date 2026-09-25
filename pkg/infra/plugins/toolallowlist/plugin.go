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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const PluginName = "tool_allowlist"

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
	canonical, err := p.registry.DecodeRequestFor(in.Request.Body, adapter.Format(format))
	if adapter.IsRequestDecodeError(err) && adapter.IsChatRequest(in.Request.ProxyCapability, adapter.Format(format)) {
		return undecodable(in)
	}
	if err != nil || canonical == nil {
		return okResult(), nil
	}
	ad, err := p.registry.GetAdapter(adapter.Format(format))
	if err != nil {
		return okResult(), nil
	}
	f := newToolFilter(ad, adapter.Format(format), in.Request.Body, canonical, cfg)
	if len(f.named) == 0 && len(f.unmodelled) == 0 {
		return f.forward(in.Mode)
	}

	kept, removed, keptCount, removedCount := f.split()
	data := ToolAllowlistData{
		Provider:       in.Request.Provider,
		ToolsRequested: f.requested(),
		ToolsAllowed:   kept,
		ToolsRemoved:   removed,
		OnEmpty:        cfg.OnEmptyAfterFilter,
		Decision:       appplugins.DecisionForMode(in.Mode),
	}

	if removedCount == 0 {
		data.Action = actionSkipped
		setExtras(in.Event, data)
		return f.forward(in.Mode)
	}

	data.Action = plannedAction(keptCount, cfg)
	setExtras(in.Event, data)

	if !appplugins.Blocks(in.Mode) {
		appplugins.SetDecision(in.Event, in.Mode)
		return okResult(), nil
	}

	if keptCount > 0 {
		return f.strip()
	}

	switch cfg.OnEmptyAfterFilter {
	case onEmptyStripField:
		return f.rewriteEmpty(true)
	case onEmptyPassThrough:
		return f.rewriteEmpty(false)
	default:
		return newRejectResult(data.ToolsRequested)
	}
}

// toolFilter applies the allow and deny patterns to one request.
type toolFilter struct {
	ad        adapter.ProviderAdapter
	body      []byte
	canonical *adapter.CanonicalRequest
	cfg       *config
	// named are the canonical tools the patterns judge by name. Outside
	// Gemini a tool with no name is judged as the unmodelled entry it
	// comes from instead, so it is not counted twice.
	named       []adapter.CanonicalTool
	unmodelled  []adapter.UnmodelledTool
	serverTypes map[string][]string
	// refusedMCP names the Anthropic MCP servers whose mcp_servers entry or
	// mcp_toolset is refused: the two go together, since Anthropic refuses
	// a toolset without its server and a server no toolset exposes.
	refusedMCP map[string]bool
	// ambiguous marks a body adapter.HasAmbiguousKeys reports: what it
	// decoded may not be what the upstream reads, so the plugin never
	// forwards the body itself.
	ambiguous bool
}

func newToolFilter(ad adapter.ProviderAdapter, format adapter.Format, body []byte, canonical *adapter.CanonicalRequest, cfg *config) *toolFilter {
	f := &toolFilter{ad: ad, body: body, canonical: canonical, cfg: cfg, ambiguous: adapter.HasAmbiguousKeys(format, body)}
	unmodelled, readable := adapter.UnmodelledTools(ad, body, canonical)
	if !readable {
		unmodelled = []adapter.UnmodelledTool{{}}
	}
	f.unmodelled = unmodelled
	for _, u := range unmodelled {
		if isMCPEntry(ad, u) && !allowsUnmodelled(ad, u, cfg) {
			if f.refusedMCP == nil {
				f.refusedMCP = map[string]bool{}
			}
			f.refusedMCP[u.Name] = true
		}
	}
	_, gemini := ad.(*adapter.GeminiAdapter)
	for _, t := range canonical.Tools {
		if t.Name != "" || gemini {
			f.named = append(f.named, t)
		}
	}
	f.serverTypes = adapter.ServerToolTypes(ad, body)
	return f
}

func (f *toolFilter) keeps(t adapter.CanonicalTool) bool {
	return keepTool(t.Name, f.serverTypes[t.Name], f.cfg)
}

// keepsUnmodelled applies allowsUnmodelled, and drops an MCP server entry
// or toolset whenever the other half of the pair is refused.
func (f *toolFilter) keepsUnmodelled(u adapter.UnmodelledTool) bool {
	if isMCPEntry(f.ad, u) && f.refusedMCP[u.Name] {
		return false
	}
	return allowsUnmodelled(f.ad, u, f.cfg)
}

func isMCPEntry(ad adapter.RequestAdapter, u adapter.UnmodelledTool) bool {
	_, anthropic := ad.(*adapter.AnthropicAdapter)
	return anthropic && (u.Kind == mcpServersKind || u.Kind == mcpToolsetKind)
}

func (f *toolFilter) requested() []string {
	out := toolNames(f.named)
	for _, u := range f.unmodelled {
		if label := unmodelledLabel(u); label != "" {
			out = append(out, label)
		}
	}
	return out
}

func (f *toolFilter) split() (kept, removed []string, keptCount, removedCount int) {
	kept = make([]string, 0, len(f.named))
	removed = make([]string, 0, len(f.named))
	add := func(label string, keep bool) {
		list := &removed
		if keep {
			keptCount++
			list = &kept
		} else {
			removedCount++
		}
		if label != "" {
			*list = append(*list, label)
		}
	}
	for _, t := range f.named {
		add(t.Name, f.keeps(t))
	}
	for _, u := range f.unmodelled {
		add(unmodelledLabel(u), f.keepsUnmodelled(u))
	}
	return kept, removed, keptCount, removedCount
}

// forward lets the request through as it came, or, when its body is
// ambiguous and the policy enforces, as the plugin decoded it.
func (f *toolFilter) forward(mode policy.Mode) (*appplugins.Result, error) {
	if !f.ambiguous || !appplugins.Blocks(mode) {
		return okResult(), nil
	}
	return f.encode()
}

func (f *toolFilter) encode() (*appplugins.Result, error) {
	body, err := f.ad.EncodeRequest(f.canonical)
	if err != nil {
		return nil, fmt.Errorf("tool_allowlist: encode: %w", err)
	}
	return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: body}, nil
}

func (f *toolFilter) strip() (*appplugins.Result, error) {
	baseline := f.canonical.Clone()
	_, gemini := f.ad.(*adapter.GeminiAdapter)
	f.canonical.Tools = adapter.FilterTools(f.canonical.Tools, func(t adapter.CanonicalTool) bool {
		return (t.Name != "" || gemini) && f.keeps(t)
	})
	adapter.DropDanglingToolChoice(f.canonical)
	body, err := adapter.GraftChangedFieldsWith(f.ad, f.body, baseline, f.canonical, adapter.GraftOptions{
		KeepUnmodelledTool: f.keepsUnmodelled,
	})
	if err != nil {
		return nil, fmt.Errorf("tool_allowlist: strip: %w", err)
	}
	return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: body}, nil
}

// toolKeys are the top-level keys that declare tools or steer their use in
// the formats the plugin reads. Bedrock and Gemini keep the choice under
// toolConfig.
var toolKeys = []string{
	"tools", "tool_choice", "parallel_tool_calls", "functions", "function_call", "mcp_servers",
	"toolConfig", "tool_config",
}

// rewriteEmpty forwards the request with no tools once the filter removed
// them all: without the tools keys, or with an empty tools array when
// deleteTools is false. An ambiguous body is re-encoded without tools
// instead. Bedrock takes no empty tools list, and refuses a conversation
// with tool calls or results but no toolConfig, so its toolConfig is
// grafted from the adapter's encoding with no tools: gone, or the
// placeholder the adapter declares for such a conversation.
func (f *toolFilter) rewriteEmpty(deleteTools bool) (*appplugins.Result, error) {
	if f.ambiguous {
		f.canonical.Tools, f.canonical.ToolChoice, f.canonical.ParallelToolCalls = nil, nil, nil
		return f.encode()
	}
	if _, bedrock := f.ad.(*adapter.BedrockAdapter); bedrock {
		return f.rewriteBedrockEmpty()
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(f.body, &m); err != nil {
		return nil, fmt.Errorf("tool_allowlist: rewrite: %w", err)
	}
	for key := range m {
		for _, k := range toolKeys {
			if strings.EqualFold(key, k) {
				delete(m, key)
			}
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

func (f *toolFilter) rewriteBedrockEmpty() (*appplugins.Result, error) {
	baseline := f.canonical.Clone()
	f.canonical.Tools, f.canonical.ToolChoice = nil, nil
	body, err := adapter.GraftChangedFieldsWith(f.ad, f.body, baseline, f.canonical, adapter.GraftOptions{
		KeepUnmodelledTool: func(adapter.UnmodelledTool) bool { return false },
	})
	if err != nil {
		return nil, fmt.Errorf("tool_allowlist: rewrite: %w", err)
	}
	return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: body}, nil
}

// undecodable fails closed on a body that does not decode in its wire
// format: the tools it declares cannot be filtered, and the upstream may
// still accept it. An observe policy only records it.
func undecodable(in appplugins.ExecInput) (*appplugins.Result, error) {
	setExtras(in.Event, ToolAllowlistData{
		Provider: in.Request.Provider,
		Action:   actionUndecodable,
		Decision: appplugins.DecisionForMode(in.Mode),
	})
	if !appplugins.Blocks(in.Mode) {
		appplugins.SetDecision(in.Event, in.Mode)
		return okResult(), nil
	}
	return nil, appplugins.UndecodableRequestError(PluginName)
}

func newRejectResult(requested []string) (*appplugins.Result, error) {
	body, err := json.Marshal(newErrorBody(requested))
	if err != nil {
		return nil, &appplugins.PluginError{
			StatusCode: http.StatusForbidden,
			Message:    "no tools allowed",
		}
	}
	return &appplugins.Result{
		StopUpstream: true,
		StatusCode:   http.StatusForbidden,
		Headers:      map[string][]string{"Content-Type": {"application/json"}},
		Body:         body,
	}, nil
}

// keepTool applies the patterns to a tool by its name and, for an Anthropic
// server tool, by its versioned type too: allow_tools must match one of
// them and deny_tools none.
func keepTool(name string, types []string, cfg *config) bool {
	ids := append([]string{name}, types...)
	if len(cfg.AllowTools) > 0 && !matchesAny(cfg.AllowTools, ids) {
		return false
	}
	return !matchesAny(cfg.DenyTools, ids)
}

func matchesAny(patterns, ids []string) bool {
	for _, id := range ids {
		if _, ok := matchAny(patterns, id); ok {
			return true
		}
	}
	return false
}

// allowsUnmodelled decides a tools entry the canonical request does not
// model. A legacy Chat function is judged by its name like any function
// tool. A built-in tool of the wire format stays when no deny pattern
// matches its kind or name and, if allow_tools is set, allow_tools names its
// kind exactly: patterns never allow such a tool, and a request left with
// only built-ins allow_tools does not name is refused (fail closed). Any
// other kind is refused, since the plugin cannot see what it would expose.
func allowsUnmodelled(ad adapter.RequestAdapter, u adapter.UnmodelledTool, cfg *config) bool {
	if u.Kind == "functions" {
		return u.Name != "" && keepTool(u.Name, nil, cfg)
	}
	if !isBuiltinTool(ad, u.Kind) || (u.Kind == mcpToolsetKind && u.Name == "") {
		return false
	}
	ids := []string{u.Kind}
	if u.Name != "" {
		ids = append(ids, u.Name)
	}
	if matchesAny(cfg.DenyTools, ids) {
		return false
	}
	return len(cfg.AllowTools) == 0 || slices.Contains(cfg.AllowTools, u.Kind)
}

// unmodelledLabel names an unmodelled entry in the event and the refusal:
// its kind, with the name for the entries of a second tools list.
func unmodelledLabel(u adapter.UnmodelledTool) string {
	if (u.Kind == "functions" || u.Kind == mcpServersKind || u.Kind == mcpToolsetKind) && u.Name != "" {
		return u.Kind + ":" + u.Name
	}
	return u.Kind
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

func matchToolPattern(pattern, name string) bool {
	const sentinel = "\x00"
	p := strings.ReplaceAll(pattern, "/", sentinel)
	n := strings.ReplaceAll(name, "/", sentinel)
	ok, err := path.Match(p, n)
	return err == nil && ok
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
