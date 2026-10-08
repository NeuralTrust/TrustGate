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
	"errors"
	"iter"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

type chatStreamOptions struct {
	includeUsage bool
	model        string
}

// ClientNotifiedStreamError marks a failure already sent in the client format.
type ClientNotifiedStreamError struct {
	Err error
}

func (e *ClientNotifiedStreamError) Error() string { return e.Err.Error() }
func (e *ClientNotifiedStreamError) Unwrap() error { return e.Err }

func adaptChatStream(
	raw iter.Seq2[[]byte, error],
	registry providerCodec,
	target adapter.Format,
	onChunk func(*adapter.CanonicalStreamChunk),
	options chatStreamOptions,
) iter.Seq2[[]byte, error] {
	stream := func(yield func([]byte, error) bool) {
		encoder := adapter.NewOpenAIChatStreamEncoder(options.includeUsage)
		var id, model, reason string
		var usage *adapter.CanonicalUsage
		var finished bool
		emit := func(lines [][]byte) bool {
			for _, line := range lines {
				if !yield(line, nil) {
					return false
				}
			}
			return true
		}
		abort := func(err error) {
			if emit(encoder.Abort("upstream stream failed")) {
				yield(nil, &ClientNotifiedStreamError{Err: err})
			}
		}
		finish := func() bool {
			if reason == "" {
				abort(errors.New("upstream stream ended without a finish reason"))
				return false
			}
			finished = true
			if model == "" {
				model = options.model
			}
			return emit(encoder.Finish(&adapter.CanonicalStreamChunk{ID: id, Model: model, FinishReason: reason, Usage: usage}))
		}
		for line, err := range raw {
			if finished {
				return
			}
			if err != nil {
				abort(err)
				return
			}
			payload, ok := dataPayload(line)
			if !ok {
				continue
			}
			chunk, err := registry.DecodeStreamChunkFor(payload, target)
			if err != nil {
				abort(err)
				return
			}
			if chunk == nil {
				continue
			}
			if onChunk != nil {
				onChunk(chunk)
			}
			if chunk.UpstreamError != nil {
				abort(chunk.UpstreamError)
				return
			}
			if message, failed := adapter.FinishFailure(chunk.FinishReason); failed {
				abort(errors.New(message))
				return
			}
			if id == "" {
				id = chunk.ID
			}
			if model == "" {
				model = chunk.Model
			}
			if target == adapter.FormatAnthropic && (id == "" || model == "") {
				abort(errors.New("upstream Anthropic stream is missing its message identity"))
				return
			}
			usage = adapter.MergeUsage(usage, chunk.Usage)
			if reason == "" && chunk.FinishReason != "" {
				reason = chunk.FinishReason
			}
			out := *chunk
			out.ID, out.Model = id, model
			if out.Model == "" {
				out.Model = options.model
			}
			if !emit(encoder.Content(&out)) {
				return
			}
			if chunk.StreamEnd {
				finish()
				return
			}
		}
		// Gemini has no separate terminal event: a valid finish needs a clean EOF.
		if adapter.IsSameWireFormat(target, adapter.FormatGemini) && reason != "" {
			finish()
			return
		}
		abort(errors.New("upstream stream ended before its terminal event"))
	}
	return coalesceOpenAIToolCallStream(stream)
}
