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

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
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
	Kind adapter.CanonicalToolKind
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
			cur = &toolCallEntry{ID: tc.ID, Kind: tc.Kind, Name: tc.Name}
			(*a)[tc.Index] = cur
		}
		if tc.Name != "" {
			cur.Name = tc.Name
		}
		if tc.ID != "" {
			cur.ID = tc.ID
		}
		if tc.Kind != adapter.ToolKindFunction {
			cur.Kind = tc.Kind
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
			Kind:           cur.Kind,
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
// onChunk, when non-nil, is invoked with every decoded upstream chunk in both
// passthrough and cross-format paths. Cross-format streams to Bedrock,
// Anthropic, Responses and Gemini clients hold the finish and usage back and
// emit them once, with the merged usage, on an upstream event its format
// guarantees final or on [DONE], or else before the upstream ends or fails;
// nothing is flushed unless the upstream sent a finish, and nothing is emitted
// after the flush. Outer/mid-stream errors from raw
// are propagated as the sequence error.
func adaptStream(
	raw iter.Seq2[[]byte, error],
	registry providerCodec,
	source, target adapter.Format,
	logger *slog.Logger,
	onChunk func(*adapter.CanonicalStreamChunk),
) iter.Seq2[[]byte, error] {
	crossFormat := !adapter.ShouldPassthroughSameWireFormat(source, target)
	geminiToolCalls := source == adapter.FormatGemini && target.SupportsCanonicalToolCalls()
	var deferred *finishDeferral
	if crossFormat {
		deferred = newFinishDeferral(source, target)
	}
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
				if deferred != nil && !deferred.flushOnError(emit, registry, source, logger) {
					return
				}
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
				if deferred != nil && !deferred.flush(emit, registry, source, logger) {
					return
				}
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
				if !emitGeminiToolCalls(emit, registry, payload, source, target, &acc, deferred, logger) {
					return
				}
				continue
			}

			if deferred != nil {
				if !emitDeferred(emit, registry, payload, source, target, deferred, logger) {
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
		if deferred != nil {
			deferred.flush(emit, registry, source, logger)
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
	registry providerCodec,
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

// emitGeminiToolCalls decodes a backend chunk, accumulates tool-call deltas,
// encodes Role/Delta/flushed-tool-calls in the source format and hands the
// finish to deferred. It returns false when the consumer stopped (yield
// returned false).
func emitGeminiToolCalls(
	emit func([][]byte) bool,
	registry providerCodec,
	payload []byte,
	source, target adapter.Format,
	acc *toolCallAccumulator,
	deferred *finishDeferral,
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

	if deferred.dropAfterFlush(canonical, source, logger) {
		return true
	}
	acc.Merge(canonical.ToolCallDeltas)
	terminal := deferred.record(canonical)

	if canonical.Role != "" {
		if !encodeAndEmit(emit, registry, &adapter.CanonicalStreamChunk{Role: canonical.Role}, source, logger) {
			return false
		}
	}
	if canonical.Delta != "" {
		if !encodeAndEmit(emit, registry, &adapter.CanonicalStreamChunk{Delta: canonical.Delta}, source, logger) {
			return false
		}
	}
	if canonical.FinishReason != "" && len(*acc) > 0 {
		if !encodeAndEmit(emit, registry, &adapter.CanonicalStreamChunk{ToolCallDeltas: acc.Flush()}, source, logger) {
			return false
		}
	}
	return !terminal || deferred.flush(emit, registry, source, logger)
}

// finishDeferral holds a cross-format stream's finish and usage until the
// upstream's usage is final, so the client gets one finish even when the
// upstream sends several.
type finishDeferral struct {
	target        adapter.Format
	holdFinish    bool
	keepRoleUsage bool
	finished      bool
	flushed       bool
	dropLogged    bool
	reason        string
	id            string
	model         string
	usage         *adapter.CanonicalUsage
}

func newFinishDeferral(source, target adapter.Format) *finishDeferral {
	switch source {
	case adapter.FormatBedrock:
		return &finishDeferral{target: target, holdFinish: true}
	case adapter.FormatAnthropic:
		return &finishDeferral{target: target, holdFinish: true, keepRoleUsage: true}
	case adapter.FormatOpenAIResponses, adapter.FormatGemini:
		return &finishDeferral{target: target, holdFinish: true}
	default:
		return nil
	}
}

// record merges chunk into d and reports whether the upstream's usage is now
// final: the upstream has finished and chunk is an event the target format
// sends only once, last, with the complete usage.
func (d *finishDeferral) record(chunk *adapter.CanonicalStreamChunk) bool {
	if d.id == "" {
		d.id = chunk.ID
	}
	if d.model == "" {
		d.model = chunk.Model
	}
	d.usage = adapter.MergeUsage(d.usage, chunk.Usage)
	if chunk.FinishReason != "" && !d.finished {
		d.finished = true
		d.reason = chunk.FinishReason
	}
	return d.finished && finalUsageEvent(d.target, chunk)
}

// finalUsageEvent reports whether chunk is the target's closing usage event:
// Anthropic message_delta, Responses response.completed, Bedrock metadata or an
// OpenAI include_usage chunk. Gemini repeats usageMetadata on every chunk and
// an OpenAI-wire finish chunk may be followed by a usage chunk, so neither is
// final; those streams flush on [DONE] or when the upstream ends.
func finalUsageEvent(target adapter.Format, chunk *adapter.CanonicalStreamChunk) bool {
	if chunk.Usage == nil {
		return false
	}
	switch {
	case target == adapter.FormatAnthropic, target == adapter.FormatOpenAIResponses:
		return chunk.FinishReason != ""
	case target == adapter.FormatBedrock, adapter.IsSameWireFormat(target, adapter.FormatOpenAI):
		return chunk.FinishReason == "" && chunk.Role == "" && chunk.Delta == "" &&
			chunk.ReasoningDelta == "" && len(chunk.ToolCallDeltas) == 0
	default:
		return false
	}
}

// dropAfterFlush reports whether chunk arrived after the flushed finish and so
// must not reach the client, logging the first such chunk.
func (d *finishDeferral) dropAfterFlush(
	chunk *adapter.CanonicalStreamChunk,
	source adapter.Format,
	logger *slog.Logger,
) bool {
	if !d.flushed {
		return false
	}
	if !d.dropLogged {
		d.dropLogged = true
		logger.Warn("stream chunk after the flushed finish dropped",
			slog.String("target", string(d.target)),
			slog.String("source", string(source)),
			slog.Bool("content", chunk.Role != "" || chunk.Delta != "" || chunk.ReasoningDelta != "" || len(chunk.ToolCallDeltas) > 0),
			slog.Bool("usage", chunk.Usage != nil),
			slog.String("finish_reason", chunk.FinishReason),
		)
	}
	return true
}

// flushOnError flushes like flush, warning first when the usage merged so far
// has no output tokens and so is likely incomplete.
func (d *finishDeferral) flushOnError(
	emit func([][]byte) bool,
	registry providerCodec,
	source adapter.Format,
	logger *slog.Logger,
) bool {
	if d.finished && !d.flushed && (d.usage == nil || d.usage.OutputTokens == 0) {
		logger.Warn("stream usage may be incomplete: upstream failed before sending output tokens",
			slog.String("target", string(d.target)),
			slog.String("source", string(source)),
		)
	}
	return d.flush(emit, registry, source, logger)
}

// flush emits the held finish with the merged usage at most once, and nothing
// when the upstream never finished. It returns false when the consumer stopped.
func (d *finishDeferral) flush(
	emit func([][]byte) bool,
	registry providerCodec,
	source adapter.Format,
	logger *slog.Logger,
) bool {
	if !d.finished || d.flushed {
		return true
	}
	d.flushed = true
	chunk := &adapter.CanonicalStreamChunk{ID: d.id, Model: d.model, Usage: d.usage}
	if d.holdFinish {
		chunk.FinishReason = d.reason
	}
	if chunk.FinishReason == "" && chunk.Usage == nil {
		return true
	}
	return encodeAndEmit(emit, registry, chunk, source, logger)
}

// emitDeferred re-encodes a chunk without its usage, and without its finish
// when deferred holds it, so the client gets them once from flush with the
// merged usage instead of per chunk, the last of which may lack the cache
// counts.
func emitDeferred(
	emit func([][]byte) bool,
	registry providerCodec,
	payload []byte,
	source, target adapter.Format,
	deferred *finishDeferral,
	logger *slog.Logger,
) bool {
	canonical, err := registry.DecodeStreamChunkFor(payload, target)
	if err != nil {
		logger.Warn("stream decode chunk failed", slog.String("error", err.Error()))
		return true
	}
	if canonical == nil || deferred.dropAfterFlush(canonical, source, logger) {
		return true
	}
	terminal := deferred.record(canonical)
	chunk := *canonical
	chunk.ProviderExtensions = nil
	if !deferred.keepRoleUsage || chunk.Role == "" {
		chunk.Usage = nil
	}
	if deferred.holdFinish {
		chunk.FinishReason = ""
	}
	if !encodeAndEmit(emit, registry, &chunk, source, logger) {
		return false
	}
	return !terminal || deferred.flush(emit, registry, source, logger)
}

func encodeAndEmit(
	emit func([][]byte) bool,
	registry providerCodec,
	chunk *adapter.CanonicalStreamChunk,
	format adapter.Format,
	logger *slog.Logger,
) bool {
	lines, err := registry.EncodeStreamChunkFor(chunk, format)
	if err != nil {
		logger.Warn("stream encode chunk failed", slog.String("error", err.Error()))
		return true
	}
	if len(lines) == 0 {
		return true
	}
	return emit(lines)
}
