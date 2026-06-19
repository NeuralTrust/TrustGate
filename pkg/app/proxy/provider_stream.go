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

package proxy

import (
	"bytes"
	"encoding/json"
	"iter"
	"log/slog"
	"sort"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
)

var (
	sseDataPrefix = []byte("data:")
	sseDoneMarker = []byte("[DONE]")
)

// injectStreamTrue sets "stream": true in a JSON request body so registries using
// the OpenAI-style API (openai, azure, anthropic, mistral) actually stream when
// the source format (e.g. Gemini) does not carry "stream" in the body.
func injectStreamTrue(body []byte) []byte {
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return body
	}
	m["stream"] = true
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

// injectStreamIncludeUsage forces "stream_options.include_usage": true on an
// OpenAI Chat Completions request body. Without it OpenAI-wire backends omit the
// final usage chunk while streaming, leaving the request metrics without token
// usage. Existing stream_options keys are preserved. It must only be applied to
// the OpenAI Chat Completions wire format: the Responses API, Anthropic and
// Mistral stream usage by default and reject (or ignore) this field.
func injectStreamIncludeUsage(body []byte) []byte {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return body
	}
	opts := map[string]json.RawMessage{}
	if raw, ok := m["stream_options"]; ok {
		_ = json.Unmarshal(raw, &opts)
	}
	opts["include_usage"] = json.RawMessage("true")
	encodedOpts, err := json.Marshal(opts)
	if err != nil {
		return body
	}
	m["stream_options"] = encodedOpts
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

// toolCallEntry holds accumulated tool call data for a single index.
type toolCallEntry struct {
	ID   string
	Name string
	Args string
}

// toolCallAccumulator merges incremental tool call deltas (e.g. from OpenAI)
// and flushes them as complete deltas (e.g. for Gemini functionCall encoding).
type toolCallAccumulator map[int]*toolCallEntry

// Merge incorporates a set of incremental deltas into the accumulator.
func (a *toolCallAccumulator) Merge(deltas []adapter.StreamToolCallDelta) {
	if len(deltas) == 0 {
		return
	}
	if *a == nil {
		*a = make(toolCallAccumulator)
	}
	for i := range deltas {
		tc := &deltas[i]
		cur := (*a)[tc.Index]
		if cur == nil {
			cur = &toolCallEntry{ID: tc.ID, Name: tc.Name}
			(*a)[tc.Index] = cur
		}
		if tc.Name != "" {
			cur.Name = tc.Name
		}
		if tc.ID != "" {
			cur.ID = tc.ID
		}
		cur.Args += tc.ArgumentsDelta
	}
}

// Flush returns all accumulated tool calls sorted by index and resets the accumulator.
func (a *toolCallAccumulator) Flush() []adapter.StreamToolCallDelta {
	indices := make([]int, 0, len(*a))
	for idx := range *a {
		indices = append(indices, idx)
	}
	sort.Ints(indices)
	deltas := make([]adapter.StreamToolCallDelta, 0, len(*a))
	for _, idx := range indices {
		cur := (*a)[idx]
		if cur == nil {
			continue
		}
		deltas = append(deltas, adapter.StreamToolCallDelta{
			Index:          idx,
			ID:             cur.ID,
			Name:           cur.Name,
			ArgumentsDelta: cur.Args,
		})
	}
	*a = nil
	return deltas
}

// adaptStream transforms a sequence of raw backend SSE lines (in the target
// provider's wire format) into the source (client) format. When the two formats
// are wire-compatible it yields each line verbatim (byte-exact passthrough);
// otherwise it routes every "data:" payload through the canonical model via the
// adapter registry. The Gemini-source + OpenAI/Responses/Anthropic/Mistral-target
// case accumulates incremental tool-call deltas and flushes them on finish.
//
// onUsage, when non-nil, is invoked with the canonical usage of any chunk that
// carries it (typically the final chunk) in both passthrough and cross-format
// paths. Outer/mid-stream errors from raw are propagated as the sequence error.
func adaptStream(
	raw iter.Seq2[[]byte, error],
	registry *adapter.Registry,
	source, target adapter.Format,
	logger *slog.Logger,
	onChunk func(*adapter.CanonicalStreamChunk),
) iter.Seq2[[]byte, error] {
	crossFormat := !adapter.ShouldPassthroughSameWireFormat(source, target)
	geminiToolCalls := source == adapter.FormatGemini &&
		(adapter.IsSameWireFormat(target, adapter.FormatOpenAI) ||
			target == adapter.FormatOpenAIResponses ||
			target == adapter.FormatAnthropic ||
			target == adapter.FormatMistral)
	// On the cross-format path the adapter re-encodes payload chunks but never
	// produces the terminating "data: [DONE]" sentinel. OpenAI-wire clients
	// (openai, azure) rely on it to detect end-of-stream, so re-emit it when the
	// source they speak expects it. Other source formats use their own terminator.
	forwardDone := crossFormat && adapter.IsSameWireFormat(source, adapter.FormatOpenAI)

	stream := func(yield func([]byte, error) bool) {
		emit := func(lines [][]byte) bool {
			for _, l := range lines {
				if !yield(l, nil) {
					return false
				}
			}
			return true
		}

		var acc toolCallAccumulator
		for line, err := range raw {
			if err != nil {
				yield(nil, err)
				return
			}

			if !crossFormat {
				if payload, ok := dataPayload(line); ok {
					observeChunk(registry, payload, target, onChunk)
				}
				if !yield(line, nil) {
					return
				}
				continue
			}

			if isSSEDone(line) {
				if forwardDone && !emit(sseDoneLines()) {
					return
				}
				continue
			}

			payload, ok := dataPayload(line)
			if !ok {
				continue
			}
			observeChunk(registry, payload, target, onChunk)

			if geminiToolCalls {
				if !emitGeminiToolCalls(emit, registry, payload, source, target, &acc, logger) {
					return
				}
				continue
			}

			lines, adaptErr := registry.AdaptStreamChunk(payload, source, target)
			if adaptErr != nil {
				logger.Warn("stream adapt chunk failed", slog.String("error", adaptErr.Error()))
				continue
			}
			if !emit(lines) {
				return
			}
			// TODO(B.3): plugin chunk forwarding hook here.
		}
	}

	if source != adapter.FormatOpenAIResponses && adapter.IsSameWireFormat(source, adapter.FormatOpenAI) {
		return coalesceOpenAIToolCallStream(stream)
	}
	return stream
}

// isSSEDone reports whether line is the SSE "data: [DONE]" end-of-stream marker.
func isSSEDone(line []byte) bool {
	if !bytes.HasPrefix(line, sseDataPrefix) {
		return false
	}
	return bytes.Equal(bytes.TrimSpace(bytes.TrimPrefix(line, sseDataPrefix)), sseDoneMarker)
}

// sseDoneLines builds the terminating "data: [DONE]" event (data line plus the
// empty separator), matching the framing produced by the adapter's SSEData.
func sseDoneLines() [][]byte {
	return [][]byte{append([]byte("data: "), sseDoneMarker...), {}}
}

// dataPayload extracts the JSON payload of an SSE "data:" line. It returns
// (nil, false) for non-data lines, empty separators, and the [DONE] marker.
func dataPayload(line []byte) ([]byte, bool) {
	if !bytes.HasPrefix(line, sseDataPrefix) {
		return nil, false
	}
	payload := bytes.TrimSpace(bytes.TrimPrefix(line, sseDataPrefix))
	if len(payload) == 0 || bytes.Equal(payload, sseDoneMarker) {
		return nil, false
	}
	return payload, true
}

// observeChunk decodes payload for the target format and reports the canonical
// chunk to onChunk. Usage lives on the final chunk and model/finish_reason on
// the first/last chunks; the observer accumulates them. Decode failures are
// ignored: observation is best-effort.
func observeChunk(
	registry *adapter.Registry,
	payload []byte,
	target adapter.Format,
	onChunk func(*adapter.CanonicalStreamChunk),
) {
	if onChunk == nil {
		return
	}
	canonical, err := registry.DecodeStreamChunkFor(payload, target)
	if err != nil || canonical == nil {
		return
	}
	onChunk(canonical)
}

// emitGeminiToolCalls decodes a backend chunk, accumulates tool-call deltas, and
// encodes Role/Delta/flushed-tool-calls/FinishReason in the source format. It
// returns false when the consumer stopped (yield returned false).
func emitGeminiToolCalls(
	emit func([][]byte) bool,
	registry *adapter.Registry,
	payload []byte,
	source, target adapter.Format,
	acc *toolCallAccumulator,
	logger *slog.Logger,
) bool {
	canonical, decErr := registry.DecodeStreamChunkFor(payload, target)
	if decErr != nil {
		logger.Warn("stream decode chunk failed", slog.String("error", decErr.Error()))
		return true
	}
	if canonical == nil {
		return true
	}

	acc.Merge(canonical.ToolCallDeltas)

	if canonical.Role != "" {
		if !encodeAndEmit(emit, registry, &adapter.CanonicalStreamChunk{Role: canonical.Role}, source) {
			return false
		}
	}
	if canonical.Delta != "" {
		if !encodeAndEmit(emit, registry, &adapter.CanonicalStreamChunk{Delta: canonical.Delta}, source) {
			return false
		}
	}
	if canonical.FinishReason != "" && len(*acc) > 0 {
		if !encodeAndEmit(emit, registry, &adapter.CanonicalStreamChunk{ToolCallDeltas: acc.Flush()}, source) {
			return false
		}
	}
	if canonical.FinishReason != "" {
		if !encodeAndEmit(emit, registry, &adapter.CanonicalStreamChunk{FinishReason: canonical.FinishReason}, source) {
			return false
		}
	}
	return true
}

func encodeAndEmit(
	emit func([][]byte) bool,
	registry *adapter.Registry,
	chunk *adapter.CanonicalStreamChunk,
	format adapter.Format,
) bool {
	lines, err := registry.EncodeStreamChunkFor(chunk, format)
	if err != nil || len(lines) == 0 {
		return true
	}
	return emit(lines)
}
