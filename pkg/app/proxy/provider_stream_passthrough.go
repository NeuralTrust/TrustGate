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

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// errPassthroughUnterminated ends a same-format stream whose upstream closed
// before the event its wire format ends a response with. It is a plain error,
// not a ClientNotifiedStreamError: the client has been told nothing, so the
// transport writes its own error event in the client's dialect.
var errPassthroughUnterminated = errors.New("upstream stream ended before its terminal event")

// passthroughEnd tracks whether a same-format upstream reached the event its
// wire format closes a response with, so that a stream ending before it
// reaches the client as a failure rather than as a finished answer.
//
// A passthrough client gets the upstream's lines verbatim, so it gets the
// upstream's own terminal event, or no terminal at all when the upstream never
// sent one. The transport tells the second case apart only when a read fails:
// an upstream that closes its body cleanly halfway through an answer, or a
// proxy in front of it that does, ends the sequence exactly as a finished one
// does, and the client was handed a truncated answer that looked complete. The
// cross-format path already refuses that ending (finishDeferral.end); this is
// the same rule for the path that does not re-encode.
//
// The terminal is what the decoders and the cross-format path already read as
// one, per wire format:
//
//   - Chat Completions, every OpenAI-wire family (Azure, Groq, DeepSeek, xAI,
//     OpenRouter) and Mistral: data: [DONE]. A finish_reason chunk is not the
//     end there: the include_usage chunk follows it.
//   - Anthropic: message_stop, which its decoder reports as StreamEnd.
//   - Cohere: message-end, likewise.
//   - Responses: response.completed and response.incomplete, likewise, and
//     response.failed, which decodes to an upstream error.
//   - Gemini and Vertex: a candidate with a finishReason. Gemini sends no
//     [DONE] and no closing event, so the finish on its last chunk is all
//     there is; finishDeferral.end accepts it the same way for a Chat
//     Completions client.
//
// [DONE] closes any of them: StreamSSE stops reading on it, and the
// cross-format path takes it as a clean close as well.
//
// An error the upstream sent in-band also settles it: OpenAI's {"error":...}
// chunk, Anthropic's and Responses' error events, Gemini's and Cohere's error
// objects. The client already read that error verbatim, in its own dialect,
// and a second one from the gateway would report the same failure twice. A
// payload the decoder could not read is not an error the upstream sent, so it
// does not settle anything.
//
// Bedrock Converse is left alone: its events reach the gateway through the AWS
// SDK's eventstream reader rather than through StreamSSE, and that reader
// reports a broken stream through an error of its own. Native Bedrock frames
// never reach adaptStream. Any format not named above is not tracked either:
// holding a stream to a terminal its upstream may not send would turn every
// finished answer into a failure.
type passthroughEnd struct {
	target  adapter.Format
	reached bool
}

// newPassthroughEnd returns the tracker for a same-format stream from target,
// or nil when the gateway does not hold that wire format to a terminal.
func newPassthroughEnd(target adapter.Format) *passthroughEnd {
	switch {
	case adapter.IsSameWireFormat(target, adapter.FormatOpenAI),
		adapter.IsSameWireFormat(target, adapter.FormatGemini),
		target == adapter.FormatMistral,
		target == adapter.FormatAnthropic,
		target == adapter.FormatOpenAIResponses,
		target == adapter.FormatCohere:
		return &passthroughEnd{target: target}
	default:
		return nil
	}
}

// pending reports whether the terminal is still owed. Only then does a payload
// need decoding on its account.
func (e *passthroughEnd) pending() bool {
	return e != nil && !e.reached
}

// settled reports whether the client already has the upstream's terminal
// event, or the error the upstream sent in its place.
func (e *passthroughEnd) settled() bool {
	return e != nil && e.reached
}

// observe records line against the terminal. chunk is its payload decoded for
// the target format, nil when the line carries none or it did not decode.
func (e *passthroughEnd) observe(line []byte, chunk *adapter.CanonicalStreamChunk) {
	if !e.pending() {
		return
	}
	switch {
	case isSSEDone(line):
		e.reached = true
	case chunk == nil:
	case chunk.StreamEnd:
		e.reached = true
	case chunk.UpstreamError != nil && !chunk.UpstreamError.DecoderFailure():
		e.reached = true
	case chunk.FinishReason != "" && adapter.IsSameWireFormat(e.target, adapter.FormatGemini):
		e.reached = true
	}
}
