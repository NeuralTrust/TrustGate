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

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/google/uuid"
)

type SpanType string

const (
	SpanLLM    SpanType = "llm"
	SpanMCP    SpanType = "mcp"
	SpanA2A    SpanType = "a2a"
	SpanPlugin SpanType = "plugin"
)

type LLMAttrs struct {
	RegistryID     string
	Provider       string
	Model          string
	SentModel      string
	RequestedModel string
	FinishReason   string
	TurnID         string
	Attempt        int
	Fallback       bool
	Pinned         bool
	Route          string
	Outcome        string
	Usage          *adapter.CanonicalUsage
}

type PluginAttrs struct {
	Stage      string
	Mode       string
	Decision   string
	Score      *float64
	ScoreLabel string
	Extras     any
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
	UpstreamStatus string
	RPCErrorCode   int
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
	s.errMsg = msg
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
	s.LLM.Usage = u
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

func (s *Span) SetExtras(extras any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensurePlugin()
	s.Plugin.Extras = extras
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

func (s *Span) SetMCPUpstream(serverName, registryID, host, catalogCode, transport, upstreamTool, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMCP()
	s.MCP.ServerName = serverName
	s.MCP.RegistryID = registryID
	s.MCP.Host = host
	s.MCP.CatalogCode = catalogCode
	s.MCP.Transport = transport
	s.MCP.UpstreamTool = upstreamTool
	s.MCP.UpstreamStatus = status
}

func (s *Span) SetMCPTargets(targets int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMCP()
	s.MCP.Targets = targets
}

func (s *Span) SetMCPStatus(status string, rpcErrorCode int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureMCP()
	s.MCP.UpstreamStatus = status
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
