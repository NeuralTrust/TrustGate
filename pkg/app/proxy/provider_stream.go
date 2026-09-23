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

// ClientNotifiedStreamError wraps an upstream stream failure an Anthropic
// client has already been sent a terminal event for in its own format, so the
// transport must not append a generic error frame of its own.
type ClientNotifiedStreamError struct {
	Err error
}

func (e *ClientNotifiedStreamError) Error() string {
	return e.Err.Error()
}

func (e *ClientNotifiedStreamError) Unwrap() error {
	return e.Err
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
// after the flush. Outer/mid-stream errors from raw are propagated as the
// sequence error.
//
// An Anthropic client whose upstream ends before a finish gets an error event
// instead, and [DONE] without a finish ends its message with end_turn. An
// error object its upstream sends as a payload (adapter.UpstreamStreamError)
// ends the stream like a mid-stream error. Once an Anthropic client has its
// terminal event for a failed upstream, the sequence error is wrapped in
// ClientNotifiedStreamError.
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
				if deferred != nil {
					ok, streamErr := deferred.fail(emit, registry, source, logger, err, nil)
					if !ok {
						return
					}
					err = streamErr
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
				if deferred != nil && !deferred.done(emit, registry, source, logger) {
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
				ok, upstreamErr := emitDeferred(emit, registry, payload, source, target, deferred, logger)
				if !ok {
					return
				}
				if upstreamErr != nil {
					if ok, streamErr := deferred.fail(emit, registry, source, logger, upstreamErr, upstreamErr); ok {
						yield(nil, streamErr)
					}
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
			deferred.end(emit, registry, source, logger)
		}
	}

	if source != adapter.FormatOpenAIResponses && adapter.IsSameWireFormat(source, adapter.FormatOpenAI) {
		return coalesceOpenAIToolCallStream(stream)
	}
	return stream
}

func logStreamFailure(
	logger *slog.Logger,
	message string,
	source, target adapter.Format,
	err error,
	upstreamErr *adapter.UpstreamStreamError,
	aborted bool,
) {
	attrs := []any{
		slog.String("target", string(target)),
		slog.String("source", string(source)),
		slog.Bool("client_aborted", aborted),
	}
	if upstreamErr != nil {
		attrs = append(attrs,
			slog.String("error_type", upstreamErr.Type),
			slog.String("error_code", upstreamErr.Code),
			slog.String("error_message", upstreamErr.Message),
		)
	} else {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	logger.Warn(message, attrs...)
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
// the first/last chunks; the observer accumulates them. Decode failures and
// chunks carrying nothing but an upstream error are ignored: observation is
// best-effort.
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
	if err != nil || canonical == nil || canonical.UpstreamErrorOnly() {
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
	if canonical == nil || canonical.UpstreamErrorOnly() {
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
	anthropic     *adapter.AnthropicStreamEncoder
}

func newFinishDeferral(source, target adapter.Format) *finishDeferral {
	switch source {
	case adapter.FormatBedrock:
		return &finishDeferral{target: target, holdFinish: true}
	case adapter.FormatAnthropic:
		return &finishDeferral{target: target, holdFinish: true, keepRoleUsage: true, anthropic: adapter.NewAnthropicStreamEncoder(target)}
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

// recordUsage merges the usage of a chunk that arrived with an upstream error,
// whose finish an Anthropic client does not get, so a finish already recorded
// is flushed with it.
func (d *finishDeferral) recordUsage(chunk *adapter.CanonicalStreamChunk) {
	if d.flushed {
		return
	}
	d.usage = adapter.MergeUsage(d.usage, chunk.Usage)
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
// has no output tokens and so is likely incomplete. An Anthropic client whose
// upstream failed before finishing gets an error event instead.
func (d *finishDeferral) flushOnError(
	emit func([][]byte) bool,
	registry providerCodec,
	source adapter.Format,
	logger *slog.Logger,
) bool {
	if !d.finished {
		return d.abort(emit, "upstream stream failed")
	}
	if !d.flushed && (d.usage == nil || d.usage.OutputTokens == 0) {
		logger.Warn("stream usage may be incomplete: upstream failed before sending output tokens",
			slog.String("target", string(d.target)),
			slog.String("source", string(source)),
		)
	}
	return d.flush(emit, registry, source, logger)
}

// end flushes when the upstream ends; an Anthropic client whose upstream ended
// without a finish gets an error event instead.
func (d *finishDeferral) end(
	emit func([][]byte) bool,
	registry providerCodec,
	source adapter.Format,
	logger *slog.Logger,
) bool {
	if !d.finished {
		if d.anthropic != nil && !d.flushed {
			logger.Warn("upstream stream ended without a finish; aborted the client stream with an error event",
				slog.String("target", string(d.target)),
				slog.String("source", string(source)),
			)
		}
		return d.abort(emit, "upstream stream ended before the message finished")
	}
	return d.flush(emit, registry, source, logger)
}

// done flushes on the upstream's [DONE]. An Anthropic client whose upstream
// sent [DONE] without a finish gets its message ended with end_turn, since
// the upstream closed the stream cleanly.
func (d *finishDeferral) done(
	emit func([][]byte) bool,
	registry providerCodec,
	source adapter.Format,
	logger *slog.Logger,
) bool {
	if d.anthropic != nil && !d.finished {
		d.finished = true
		d.reason = "stop"
	}
	return d.flush(emit, registry, source, logger)
}

// clientAborted reports whether an Anthropic client got an error event in
// place of message_stop.
func (d *finishDeferral) clientAborted() bool {
	return d.anthropic != nil && d.anthropic.Aborted()
}

// fail flushes or aborts the client stream for an upstream that failed with
// err, or sent upstreamErr as a payload, and returns the sequence error to
// yield. It returns false when the consumer stopped.
func (d *finishDeferral) fail(
	emit func([][]byte) bool,
	registry providerCodec,
	source adapter.Format,
	logger *slog.Logger,
	err error,
	upstreamErr *adapter.UpstreamStreamError,
) (bool, error) {
	terminated := d.flushed
	if !d.flushOnError(emit, registry, source, logger) {
		return false, nil
	}
	if d.anthropic == nil {
		return true, err
	}
	aborted := d.clientAborted()
	message := "upstream stream failed; the client stream ended with its terminal event"
	switch {
	case terminated:
		message = "upstream stream failed after the client got its terminal event"
	case aborted:
		message = "upstream stream failed; aborted the client stream with an error event"
	}
	logStreamFailure(logger, message, source, d.target, err, upstreamErr, aborted)
	return true, &ClientNotifiedStreamError{Err: err}
}

func (d *finishDeferral) abort(emit func([][]byte) bool, message string) bool {
	if d.anthropic == nil || d.flushed {
		return true
	}
	d.flushed = true
	return emit(d.anthropic.Abort(message))
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
	if d.anthropic != nil {
		lines := d.anthropic.Finish(chunk)
		d.logFinish(chunk.FinishReason, source, logger)
		return emit(lines)
	}
	return encodeAndEmit(emit, registry, chunk, source, logger)
}

// logFinish warns about a finish an Anthropic client cannot be told
// faithfully: one reporting an upstream failure, which it gets as an error
// event, one whose tool call content it did not get, or one it gets as a plain
// end_turn.
func (d *finishDeferral) logFinish(reason string, source adapter.Format, logger *slog.Logger) {
	_, failed := adapter.FinishFailure(reason)
	deltas, tools := d.anthropic.Dropped()
	unmapped := !d.anthropic.Aborted() && adapter.AnthropicStopReasonUnmapped(reason)
	var message string
	switch {
	case failed:
		message = "upstream finished the stream with a failure reason"
	case deltas > 0 || tools > 0:
		message = "anthropic stream dropped tool call content"
	case unmapped:
		message = "upstream finish reason has no Anthropic stop_reason; sent end_turn"
	default:
		return
	}
	logger.Warn(message,
		slog.String("target", string(d.target)),
		slog.String("source", string(source)),
		slog.String("finish_reason", reason),
		slog.Bool("client_aborted", d.clientAborted()),
		slog.Int("argument_deltas", deltas),
		slog.Int("nameless_tool_calls", tools),
		slog.Bool("stop_reason_unmapped", unmapped),
	)
}

func (d *finishDeferral) encode(
	emit func([][]byte) bool,
	registry providerCodec,
	chunk *adapter.CanonicalStreamChunk,
	source adapter.Format,
	logger *slog.Logger,
) bool {
	if d.anthropic == nil {
		return encodeAndEmit(emit, registry, chunk, source, logger)
	}
	lines := d.anthropic.Content(chunk)
	return len(lines) == 0 || emit(lines)
}

// emitDeferred re-encodes a chunk without its usage, and without its finish
// when deferred holds it, so the client gets them once from flush with the
// merged usage instead of per chunk, the last of which may lack the cache
// counts. It returns false when the consumer stopped, and, for an Anthropic
// client, the error the upstream sent in payload, if any, after emitting the
// content that came with it; other clients get the rest of that payload as
// usual.
func emitDeferred(
	emit func([][]byte) bool,
	registry providerCodec,
	payload []byte,
	source, target adapter.Format,
	deferred *finishDeferral,
	logger *slog.Logger,
) (bool, *adapter.UpstreamStreamError) {
	canonical, err := registry.DecodeStreamChunkFor(payload, target)
	if err != nil {
		logger.Warn("stream decode chunk failed", slog.String("error", err.Error()))
		return true, nil
	}
	if canonical == nil {
		return true, nil
	}
	if canonical.UpstreamError != nil {
		if deferred.anthropic != nil {
			deferred.recordUsage(canonical)
			content := adapter.CanonicalStreamChunk{
				ID:             canonical.ID,
				Model:          canonical.Model,
				Role:           canonical.Role,
				Delta:          canonical.Delta,
				ToolCallDeltas: canonical.ToolCallDeltas,
			}
			if !deferred.encode(emit, registry, &content, source, logger) {
				return false, nil
			}
			return true, canonical.UpstreamError
		}
		if canonical.UpstreamErrorOnly() {
			return true, nil
		}
	}
	if deferred.dropAfterFlush(canonical, source, logger) {
		return true, nil
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
	if !deferred.encode(emit, registry, &chunk, source, logger) {
		return false, nil
	}
	return !terminal || deferred.flush(emit, registry, source, logger), nil
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
