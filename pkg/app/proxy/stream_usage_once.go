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
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// usageOnce holds the finish chunk of a re-encoded OpenAI-wire stream so the
// client gets the usage once. Groq sends the usage on the finish chunk and
// again in the include_usage chunk, and clients that sum usage across chunks
// would count it twice (ENG-1618). An OpenAI Chat Completions client gets the
// usage on the include_usage chunk when one follows the finish, and otherwise
// on the finish chunk. A Mistral client gets it on the finish chunk, as Mistral
// streams it, and the include_usage chunk is dropped. OpenRouter can send the
// include_usage chunk with a role delta; after a finish such a chunk still
// counts as the include_usage chunk and loses the role.
type usageOnce struct {
	registry      providerCodec
	source        adapter.Format
	target        adapter.Format
	logger        *slog.Logger
	usageOnFinish bool
	finished      bool
	pending       *adapter.CanonicalStreamChunk
}

// newUsageOnce returns a usageOnce for an OpenAI Chat Completions client of a
// re-encoded OpenAI-wire upstream or a Mistral client of a Groq or OpenRouter
// upstream, or nil for any other stream.
func newUsageOnce(registry providerCodec, source, target adapter.Format, crossFormat bool, logger *slog.Logger) *usageOnce {
	if !crossFormat || !adapter.IsSameWireFormat(target, adapter.FormatOpenAI) {
		return nil
	}
	u := &usageOnce{registry: registry, source: source, target: target, logger: logger}
	switch {
	case source == adapter.FormatMistral && (target == adapter.FormatGroq || target == adapter.FormatOpenRouter):
		u.usageOnFinish = true
		return u
	case source != adapter.FormatOpenAIResponses && adapter.IsSameWireFormat(source, adapter.FormatOpenAI):
		return u
	default:
		return nil
	}
}

// adapt re-encodes payload for the client and returns false when the
// consumer stopped.
func (u *usageOnce) adapt(emit func([][]byte) bool, payload []byte) bool {
	chunk, err := u.registry.DecodeStreamChunkFor(payload, u.target)
	if err != nil {
		u.logger.Warn("stream adapt chunk failed", slog.String("error", err.Error()))
		return true
	}
	if chunk == nil || chunk.UpstreamErrorOnly() {
		return true
	}
	chunk.ProviderExtensions = nil

	if u.finished && usageOnly(chunk) {
		chunk.Role = ""
		if u.pending != nil {
			if u.usageOnFinish {
				u.pending.Usage = adapter.MergeUsage(u.pending.Usage, chunk.Usage)
				return u.flush(emit)
			}
			chunk.Usage = adapter.MergeUsage(u.pending.Usage, chunk.Usage)
			u.pending.Usage = nil
			if !u.flush(emit) {
				return false
			}
		}
		return encodeAndEmit(emit, u.registry, chunk, u.source, u.logger)
	}
	if !u.flush(emit) {
		return false
	}
	if chunk.FinishReason != "" {
		u.finished = true
		if u.usageOnFinish || chunk.Usage != nil {
			u.pending = chunk
			return true
		}
	}
	return encodeAndEmit(emit, u.registry, chunk, u.source, u.logger)
}

// flush emits the held finish chunk, if any, and returns false when the
// consumer stopped.
func (u *usageOnce) flush(emit func([][]byte) bool) bool {
	if u.pending == nil {
		return true
	}
	chunk := u.pending
	u.pending = nil
	return encodeAndEmit(emit, u.registry, chunk, u.source, u.logger)
}

func usageOnly(chunk *adapter.CanonicalStreamChunk) bool {
	return chunk.Usage != nil && chunk.FinishReason == "" && chunk.Delta == "" &&
		chunk.ReasoningDelta == "" && len(chunk.ToolCallDeltas) == 0
}
