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

package adapter

import "encoding/json"

// MetadataUsageKey is the RequestContext.Metadata key under which the streaming
// usage observer records the latest *CanonicalUsage. The metrics pipeline reads
// it back from the same key when building the exchange.
const MetadataUsageKey = "usage"

// CanonicalRequest is the internal neutral representation of any AI provider
type CanonicalRequest struct {
	Model             string                     `json:"model,omitempty"`
	System            string                     `json:"system,omitempty"`
	Messages          []CanonicalMessage         `json:"messages,omitempty"`
	Tools             []CanonicalTool            `json:"tools,omitempty"`
	ToolChoice        *CanonicalToolChoice       `json:"tool_choice,omitempty"`
	MaxTokens         int                        `json:"max_tokens,omitempty"`
	Temperature       *float64                   `json:"temperature,omitempty"`
	TopP              *float64                   `json:"top_p,omitempty"`
	TopK              *int                       `json:"top_k,omitempty"`
	Stop              []string                   `json:"stop,omitempty"`
	Stream            bool                       `json:"stream,omitempty"`
	ResponseFormat    *CanonicalRespFormat       `json:"response_format,omitempty"`
	Metadata          map[string]interface{}     `json:"metadata,omitempty"`
	RequestExtensions map[string]json.RawMessage `json:"request_extensions,omitempty"`
}

// CanonicalMessage represents a single turn in the conversation.
type CanonicalMessage struct {
	Role       string              `json:"role"`
	Content    string              `json:"content"`
	ToolCalls  []CanonicalToolCall `json:"tool_calls,omitempty"`
	ToolCallID string              `json:"tool_call_id,omitempty"`
}

// CanonicalToolKind distinguishes the tool shapes the gateway can represent.
// The zero value is ToolKindFunction so tools built before custom tools existed
// keep their meaning.
type CanonicalToolKind string

const (
	// ToolKindFunction is a JSON-schema tool (OpenAI "function", Anthropic tool).
	ToolKindFunction CanonicalToolKind = ""
	// ToolKindCustom is a freeform tool that takes raw text instead of a JSON
	// schema (OpenAI "custom" tools, introduced with GPT-5).
	ToolKindCustom CanonicalToolKind = "custom"
)

// CanonicalTool represents a tool/function the model can call.
type CanonicalTool struct {
	Kind        CanonicalToolKind      `json:"kind,omitempty"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Schema      map[string]interface{} `json:"schema,omitempty"`
	// Format carries the grammar/format payload of a ToolKindCustom tool
	// verbatim. It is nil for function tools.
	Format json.RawMessage `json:"format,omitempty"`
}

// CanonicalToolChoice controls how the model selects tools.
type CanonicalToolChoice struct {
	// Type: "auto", "none", "any", "tool"
	Type string `json:"type"`
	// Name is only set when Type == "tool"
	Name string `json:"name,omitempty"`
}

// CanonicalToolCall represents a tool invocation by the model.
type CanonicalToolCall struct {
	ID   string            `json:"id"`
	Kind CanonicalToolKind `json:"kind,omitempty"`
	Name string            `json:"name"`
	// Arguments holds a raw JSON string for function calls and the freeform
	// text input for ToolKindCustom calls.
	Arguments string `json:"arguments"`
}

// CanonicalRespFormat controls the response format.
type CanonicalRespFormat struct {
	Type string `json:"type"` // "json_object", "text"
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

// CanonicalResponse is the internal neutral representation of a provider
// response.
type CanonicalResponse struct {
	ID                 string                     `json:"id,omitempty"`
	Model              string                     `json:"model,omitempty"`
	Content            string                     `json:"content,omitempty"`
	Role               string                     `json:"role,omitempty"`
	ToolCalls          []CanonicalToolCall        `json:"tool_calls,omitempty"`
	FinishReason       string                     `json:"finish_reason,omitempty"` // "stop", "length", "tool_calls"
	Usage              *CanonicalUsage            `json:"usage,omitempty"`
	Reasoning          *CanonicalReasoning        `json:"reasoning,omitempty"` // e.g. OpenAI reasoning / thinking
	ProviderExtensions map[string]json.RawMessage `json:"provider_extensions,omitempty"`
}

// CanonicalReasoning holds optional reasoning/thinking metadata from the model.
// OpenAI uses Effort/Summary; Anthropic/Gemini use ThinkingText (raw thinking content).
type CanonicalReasoning struct {
	Effort       []byte  `json:"effort,omitempty"`        // OpenAI: provider-specific (e.g. JSON)
	Summary      *string `json:"summary,omitempty"`       // OpenAI: summary
	ThinkingText string  `json:"thinking_text,omitempty"` // Anthropic/Gemini: raw thinking blocks concatenated
}

// CanonicalUsage holds token counts in a provider-neutral split: Input / Output / Total.
// InputTokens and OutputTokens are the whole prompt and the whole completion as
// the provider bills them, whatever rate each token falls under. Every other
// count names a sub-population of one of those two that bills at a different
// rate, and is always a strict subset of its parent: providers that report a
// count beside its parent rather than inside it are folded in by their adapter,
// so one pricing expression is correct everywhere. CachedInputTokens and
// CacheWriteInputTokens are also disjoint from each other. The nil-on-absence
// and total-synthesis contracts live in newCanonicalUsage.
type CanonicalUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	TotalTokens  int `json:"total_tokens"`

	CachedInputTokens     int `json:"cached_input_tokens,omitempty"`
	CacheWriteInputTokens int `json:"cache_write_input_tokens,omitempty"`
	ToolUseInputTokens    int `json:"tool_use_input_tokens,omitempty"`
	ReasoningOutputTokens int `json:"reasoning_output_tokens,omitempty"`

	// CacheWrite1hInputTokens is the share of CacheWriteInputTokens written with
	// Anthropic's one-hour TTL, which bills at 2x input where the five-minute
	// default bills at 1.25x. Carried because the wire reports it; not yet priced
	// separately, since the catalog publishes a single cache-write rate.
	CacheWrite1hInputTokens int `json:"cache_write_1h_input_tokens,omitempty"`

	ServiceTier string `json:"service_tier,omitempty"`
}

// PlainInputTokens is the share of the prompt that bills at the plain input
// rate, once the sub-populations with their own rates are removed.
func (u *CanonicalUsage) PlainInputTokens() int {
	if u == nil {
		return 0
	}
	plain := u.InputTokens - u.CachedInputTokens - u.CacheWriteInputTokens
	if plain < 0 {
		return u.InputTokens
	}
	return plain
}

// MergeUsage folds a later usage report into an earlier one, keeping the larger
// of every count. Providers stream usage in pieces and do not all repeat every
// field: Anthropic reports the prompt and both cache buckets on message_start
// and the completion on message_delta, so a later event that omits a field must
// not erase what an earlier one established. Token counts within a request only
// ever grow, which is what makes the larger value the right one to keep.
func MergeUsage(prev, next *CanonicalUsage) *CanonicalUsage {
	if prev == nil {
		return next
	}
	if next == nil {
		return prev
	}
	out := *prev
	out.InputTokens = maxTokens(prev.InputTokens, next.InputTokens)
	out.OutputTokens = maxTokens(prev.OutputTokens, next.OutputTokens)
	out.TotalTokens = maxTokens(prev.TotalTokens, next.TotalTokens)
	out.CachedInputTokens = maxTokens(prev.CachedInputTokens, next.CachedInputTokens)
	out.CacheWriteInputTokens = maxTokens(prev.CacheWriteInputTokens, next.CacheWriteInputTokens)
	out.CacheWrite1hInputTokens = maxTokens(prev.CacheWrite1hInputTokens, next.CacheWrite1hInputTokens)
	out.ToolUseInputTokens = maxTokens(prev.ToolUseInputTokens, next.ToolUseInputTokens)
	out.ReasoningOutputTokens = maxTokens(prev.ReasoningOutputTokens, next.ReasoningOutputTokens)
	if next.ServiceTier != "" {
		out.ServiceTier = next.ServiceTier
	}
	if sum := out.InputTokens + out.OutputTokens; out.TotalTokens < sum {
		out.TotalTokens = sum
	}
	return &out
}

func maxTokens(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// newCanonicalUsage returns the canonical usage view, or nil when no tokens are
// reported. When the provider does not emit a total, it is synthesized as in+out.
//
// Adapters MUST funnel their wire-struct decode through this factory so the
// "nil-on-absence" contract on CanonicalUsage is enforced in code, not prose.
func newCanonicalUsage(in, out, total int) *CanonicalUsage {
	if in == 0 && out == 0 && total == 0 {
		return nil
	}
	if total == 0 {
		total = in + out
	}
	return &CanonicalUsage{
		InputTokens:  in,
		OutputTokens: out,
		TotalTokens:  total,
	}
}

// ---------------------------------------------------------------------------
// Stream chunk types
// ---------------------------------------------------------------------------

// StreamToolCallDelta is one tool-call delta in a streamed response (OpenAI
// streams tool_calls with incremental arguments; Anthropic uses input_json_delta).
type StreamToolCallDelta struct {
	Index int               `json:"index"`
	ID    string            `json:"id,omitempty"`
	Kind  CanonicalToolKind `json:"kind,omitempty"`
	Name  string            `json:"name,omitempty"`
	// ArgumentsDelta is an incremental piece of the JSON arguments, or of the
	// freeform text input when Kind is ToolKindCustom.
	ArgumentsDelta string `json:"arguments_delta,omitempty"`
}

// CanonicalStreamChunk is one piece of a streamed response.
type CanonicalStreamChunk struct {
	ID                 string                     `json:"id,omitempty"`
	Model              string                     `json:"model,omitempty"`
	Role               string                     `json:"role,omitempty"`  // only on first chunk
	Delta              string                     `json:"delta,omitempty"` // text content delta
	ReasoningDelta     string                     `json:"reasoning_delta,omitempty"`
	FinishReason       string                     `json:"finish_reason,omitempty"`
	ToolCallDeltas     []StreamToolCallDelta      `json:"tool_call_deltas,omitempty"`
	Usage              *CanonicalUsage            `json:"usage,omitempty"` // present in the final chunk of some providers
	ProviderExtensions map[string]json.RawMessage `json:"provider_extensions,omitempty"`
}
