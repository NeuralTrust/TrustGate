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
	RegistryID   string
	Provider     string
	Model        string
	FinishReason string
	Attempt      int
	Fallback     bool
	Outcome      string
	Usage        *adapter.CanonicalUsage
}

type PluginAttrs struct {
	Stage      string
	Mode       string
	Decision   string
	Score      *float64
	ScoreLabel string
	Extras     any
}

type Span struct {
	ID        string
	ParentID  string
	Type      SpanType
	Name      string
	StartedAt time.Time

	LLM    *LLMAttrs
	Plugin *PluginAttrs

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
	if spanType == SpanPlugin {
		s.Plugin = &PluginAttrs{}
	} else {
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
