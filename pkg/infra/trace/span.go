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

package trace

import (
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common/valuecopy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/logredact"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/google/uuid"
)

type SpanType string

const (
	SpanLLM    SpanType = "llm"
	SpanMCP    SpanType = "mcp"
	SpanA2A    SpanType = "a2a"
	SpanPlugin SpanType = "plugin"
)

type RouteBaseline struct {
	Provider string
	Model    string
	Pricing  *registrydomain.Pricing
}

type LLMAttrs struct {
	RegistryID string
	Provider   string
	Model      string
	SentModel  string
	// RouteModel is the model the load balancer's route pinned, empty when the
	// route deferred to the registry's model policy. It separates the balancer's
	// decision from RequestedModel (what the client asked for) and SentModel
	// (what actually went upstream), which otherwise coincide.
	RouteModel     string
	RequestedModel string
	FinishReason   string
	TurnID         string
	Attempt        int
	Fallback       bool
	Pinned         bool
	Route          string
	Outcome        string
	Usage          *adapter.CanonicalUsage
	TierApplied    bool
	Baseline       *RouteBaseline
	ServedPricing  *registrydomain.Pricing
}

type PluginAttrs struct {
	Stage      string
	Mode       string
	Decision   string
	Score      *float64
	ScoreLabel string
	Extras     any
	// Streamed marks a policy that inspected the response block by block while
	// it drained. Stage alone cannot say so: the stream chain is forced to
	// pre_response, so a streamed leg is indistinguishable from one that ran
	// before the response was sent. The metrics fold needs the difference
	// because a streamed leg's latency elapses inside the provider span and is
	// therefore already counted in provider_ms.
	Streamed bool
}

type MCPAttrs struct {
	Method         string
	Operation      string
	ServerName     string
	RegistryID     string
	Host           string
	CatalogCode    string
	Transport      string
	Tool           string
	UpstreamTool   string
	Prompt         string
	ResourceURI    string
	Targets        int
	UpstreamStatus int
	RPCErrorCode   int
	AccountRef     string
	PolicyScope    *MCPPolicyScope
	// Decision records a tools/call-level outcome the individual per-plugin
	// spans (Plugin.Decision on a SpanPlugin entry) cannot carry, because
	// nothing ran long enough to open one: PluginRunner failing open on a
	// non-block error (including a request context it could not even build).
	// See SetMCPDecision.
	Decision string
}

// MCPPolicyScope records how the scoped policies of a consumer applied to one
// tools/call: how many were evaluated, the ids of those that entered the plan
// and those left out with the dimension that rejected them. Unscoped policies
// are never listed.
type MCPPolicyScope struct {
	Evaluated int
	Matched   []string
	Skipped   []MCPSkippedPolicy
}

// MCPSkippedPolicy names a scoped policy that did not run and why:
// destination, principal or except.
type MCPSkippedPolicy struct {
	ID     string
	Name   string
	Reason string
}

type Span struct {
	ID        string
	ParentID  string
	Type      SpanType
	Name      string
	StartedAt time.Time

	LLM    *LLMAttrs
	Plugin *PluginAttrs
	MCP    *MCPAttrs

	mu         sync.Mutex
	endedAt    time.Time
	statusCode int
	errMsg     string
	latency    time.Duration
	latencySet bool
}

func newSpan(spanType SpanType, name string) *Span {
	s := &Span{
		ID:        uuid.New().String(),
		Type:      spanType,
		Name:      name,
		StartedAt: time.Now(),
	}
	switch spanType {
	case SpanPlugin:
		s.Plugin = &PluginAttrs{}
	case SpanMCP:
		s.MCP = &MCPAttrs{}
	default:
		s.LLM = &LLMAttrs{}
	}
	return s
}

func (s *Span) End() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.endedAt.IsZero() {
		s.endedAt = time.Now()
	}
}

func (s *Span) EndedAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.endedAt
}

func (s *Span) Latency() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.latencySet {
		return s.latency
	}
	if s.endedAt.IsZero() {
		return 0
	}
	return s.endedAt.Sub(s.StartedAt)
}

func (s *Span) SetLatency(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.latency = d
	s.latencySet = true
}

// SetLatencyDefault records d only if nothing has set the latency yet, leaving
// an explicit figure untouched. A stream span opens on the first block and ends
// when the stream does, so falling back to its wall clock would charge the
// policy the whole drain; the stream chain uses this to guarantee a figure even
// when the inspector that would have set one failed first.
func (s *Span) SetLatencyDefault(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.latencySet {
		return
	}
	s.latency = d
	s.latencySet = true
}

func (s *Span) SetStatusCode(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statusCode = code
}

func (s *Span) StatusCode() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statusCode
}

func (s *Span) SetError(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errMsg = logredact.RedactLogString(msg)
}

func (s *Span) Error() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.errMsg
}

func (s *Span) ObserveUsage(u *adapter.CanonicalUsage) {
	if u == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.LLM == nil {
		s.LLM = &LLMAttrs{}
	}
	s.LLM.Usage = adapter.MergeUsage(s.LLM.Usage, u)
}

func (s *Span) Usage() *adapter.CanonicalUsage {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.LLM == nil {
		return nil
	}
	return s.LLM.Usage
}

func (s *Span) SetLLMResult(model, finishReason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.LLM == nil {
		s.LLM = &LLMAttrs{}
	}
	if model != "" {
		s.LLM.Model = model
	}
	if finishReason != "" {
		s.LLM.FinishReason = finishReason
	}
}

func (s *Span) SetTurnID(turnID string) {
	if turnID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.LLM == nil {
		s.LLM = &LLMAttrs{}
	}
	s.LLM.TurnID = turnID
}

func (s *Span) SetStage(stage string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePlugin()
	s.Plugin.Stage = stage
}

// SetStreamed marks the span as a policy that ran during stream drain. It is
// set once, when the stream opens the span, and never cleared.
func (s *Span) SetStreamed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePlugin()
	s.Plugin.Streamed = true
}

func (s *Span) SetMode(mode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePlugin()
	s.Plugin.Mode = mode
}

func (s *Span) SetDecision(decision string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePlugin()
	s.Plugin.Decision = decision
}

func (s *Span) HasDecision() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Plugin != nil && s.Plugin.Decision != ""
}

// SetExtras records a plugin's own metadata on the span, taking ownership of it.
//
// The copy is the point. What arrives here is the very struct or map the plugin
// built, and the span outlives the request: the metrics worker marshals these
// extras later, from events.SanitizeExtras. Keeping the plugin's map would mean
// the encoder walking something the request path can still mutate, which under
// Go 1.27 is a process-level panic rather than a garbled field — see the
// valuecopy package and RUN-1261.
func (s *Span) SetExtras(extras any) {
	owned := valuecopy.Deep(extras)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePlugin()
	s.Plugin.Extras = owned
}

func (s *Span) SetScore(score float64, label string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePlugin()
	s.Plugin.Score = &score
	s.Plugin.ScoreLabel = label
}

func (s *Span) ensurePlugin() {
	if s.Plugin == nil {
		s.Plugin = &PluginAttrs{}
	}
}

func (s *Span) LLMAttrsCopy() (LLMAttrs, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.LLM == nil {
		return LLMAttrs{}, false
	}
	return *s.LLM, true
}

func (s *Span) PluginAttrsCopy() PluginAttrs {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Plugin == nil {
		return PluginAttrs{}
	}
	return *s.Plugin
}

func (s *Span) ensureMCP() {
	if s.MCP == nil {
		s.MCP = &MCPAttrs{}
	}
}

func (s *Span) SetMCPRequest(method, operation, tool, prompt, resourceURI string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMCP()
	s.MCP.Method = method
	s.MCP.Operation = operation
	s.MCP.Tool = tool
	s.MCP.Prompt = prompt
	s.MCP.ResourceURI = resourceURI
}

func (s *Span) SetMCPUpstream(serverName, registryID, host, catalogCode, transport, upstreamTool string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMCP()
	s.MCP.ServerName = serverName
	s.MCP.RegistryID = registryID
	s.MCP.Host = host
	s.MCP.CatalogCode = catalogCode
	s.MCP.Transport = transport
	s.MCP.UpstreamTool = upstreamTool
}

// SetMCPPolicyScope stamps the scope decision of a tools/call next to the
// upstream. The span takes its own copy of the slices, so the caller may reuse
// them once this returns.
func (s *Span) SetMCPPolicyScope(scope MCPPolicyScope) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMCP()
	stored := MCPPolicyScope{Evaluated: scope.Evaluated}
	if len(scope.Matched) > 0 {
		stored.Matched = append([]string(nil), scope.Matched...)
	}
	if len(scope.Skipped) > 0 {
		stored.Skipped = append([]MCPSkippedPolicy(nil), scope.Skipped...)
	}
	s.MCP.PolicyScope = &stored
}

func (s *Span) SetMCPAccountRef(accountRef string) {
	if accountRef == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMCP()
	s.MCP.AccountRef = accountRef
}

func (s *Span) SetMCPTargets(targets int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMCP()
	s.MCP.Targets = targets
}

// SetMCPDecision records the tools/call-level outcome directly on the MCP
// span. It exists next to Plugin.Decision (set by SetDecision /
// SetDecisionFromOutcome on a SpanPlugin entry) because a PluginRunner
// fail-open can happen before any policy's own span was ever opened — a
// request context the runner could not build, or an executor error that was
// never wrapped into a per-plugin outcome — leaving nothing else on the trace
// for that failure to attach to.
func (s *Span) SetMCPDecision(decision string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMCP()
	s.MCP.Decision = decision
}

// SetMCPStatus records the logical HTTP status for MCP metrics and http.response.status_code.
func (s *Span) SetMCPStatus(httpStatus, rpcErrorCode int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMCP()
	s.MCP.UpstreamStatus = httpStatus
	s.MCP.RPCErrorCode = rpcErrorCode
}

func (s *Span) MCPAttrsCopy() (MCPAttrs, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.MCP == nil {
		return MCPAttrs{}, false
	}
	return *s.MCP, true
}
