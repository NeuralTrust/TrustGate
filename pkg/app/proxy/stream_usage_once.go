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

// usageOnce holds an OpenAI-wire finish chunk that carries usage until the
// next upstream event. Groq sends the usage on the finish chunk and again in
// the include_usage chunk, and clients that sum usage across chunks would
// count it twice (ENG-1618); when the include_usage chunk follows, the usage
// moves to it, and otherwise the finish chunk keeps it.
type usageOnce struct {
	registry providerCodec
	source   adapter.Format
	target   adapter.Format
	logger   *slog.Logger
	pending  *adapter.CanonicalStreamChunk
}

// newUsageOnce returns a usageOnce for an OpenAI Chat Completions client of a
// re-encoded OpenAI-wire upstream, or nil for any other stream.
func newUsageOnce(registry providerCodec, source, target adapter.Format, crossFormat bool, logger *slog.Logger) *usageOnce {
	if !crossFormat || source == adapter.FormatOpenAIResponses ||
		!adapter.IsSameWireFormat(source, adapter.FormatOpenAI) ||
		!adapter.IsSameWireFormat(target, adapter.FormatOpenAI) {
		return nil
	}
	return &usageOnce{registry: registry, source: source, target: target, logger: logger}
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

	if u.pending != nil && finalUsageEvent(u.target, chunk) {
		chunk.Usage = adapter.MergeUsage(u.pending.Usage, chunk.Usage)
		u.pending.Usage = nil
		if !u.flush(emit) {
			return false
		}
		return encodeAndEmit(emit, u.registry, chunk, u.source, u.logger)
	}
	if !u.flush(emit) {
		return false
	}
	if chunk.FinishReason != "" && chunk.Usage != nil {
		u.pending = chunk
		return true
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
