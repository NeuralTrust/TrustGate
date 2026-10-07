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
	"encoding/json"
	"errors"
	"iter"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func openAIChatIncludesUsage(body []byte) bool {
	var request struct {
		StreamOptions struct {
			IncludeUsage bool `json:"include_usage"`
		} `json:"stream_options"`
	}
	return json.Unmarshal(body, &request) == nil && request.StreamOptions.IncludeUsage
}

func withStreamIncludeUsage(includeUsage bool) streamOption {
	return func(options *streamOptions) { options.includeUsage = includeUsage }
}

func adaptAnthropicChatStream(
	raw iter.Seq2[[]byte, error],
	registry providerCodec,
	source adapter.Format,
	logger *slog.Logger,
	onChunk func(*adapter.CanonicalStreamChunk),
	options streamOptions,
) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		defer options.cancel()
		emit := func(lines [][]byte) bool {
			for _, line := range lines {
				if !yield(line, nil) {
					return false
				}
			}
			return true
		}
		var id, model, finish string
		var usage *adapter.CanonicalUsage
		for line, err := range raw {
			if err != nil {
				yield(nil, err)
				return
			}
			payload, ok := dataPayload(line)
			if !ok {
				continue
			}
			if err := adapter.ValidateAnthropicStreamEvent(payload); err != nil {
				yield(nil, err)
				return
			}
			var event struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(payload, &event) != nil {
				yield(nil, errors.New("upstream Anthropic stream sent an invalid event"))
				return
			}
			switch event.Type {
			case "error":
				yield(nil, errors.New("upstream Anthropic stream failed"))
				return
			case "message_stop":
				if finish == "" {
					yield(nil, errors.New("upstream Anthropic stream stopped without a finish"))
					return
				}
				final := &adapter.CanonicalStreamChunk{ID: id, Model: model, FinishReason: finish}
				if !encodeAndEmit(emit, registry, final, source, logger) {
					return
				}
				if options.includeUsage && usage != nil {
					final.FinishReason, final.Usage = "", usage
					if !encodeAndEmit(emit, registry, final, source, logger) {
						return
					}
				}
				emit(sseDoneLines())
				return
			}
			chunk, err := registry.DecodeStreamChunkFor(payload, adapter.FormatAnthropic)
			if err != nil {
				yield(nil, err)
				return
			}
			if chunk == nil {
				continue
			}
			if id == "" {
				id = chunk.ID
			}
			if model == "" {
				model = chunk.Model
			}
			if id == "" || model == "" {
				yield(nil, errors.New("upstream Anthropic stream omitted message identity"))
				return
			}
			if onChunk != nil {
				onChunk(chunk)
			}
			usage = adapter.MergeUsage(usage, chunk.Usage)
			if finish == "" {
				finish = chunk.FinishReason
			}
			out := *chunk
			out.ID, out.Model, out.FinishReason, out.Usage = id, model, "", nil
			if out.Role == "" && out.Delta == "" && out.ReasoningDelta == "" && len(out.ToolCallDeltas) == 0 {
				continue
			}
			if !encodeAndEmit(emit, registry, &out, source, logger) {
				return
			}
		}
		yield(nil, errors.New("upstream Anthropic stream ended before message_stop"))
	}
}
