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

package trustguard

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const streamIDSeparator = ":"

// segmentStreamID derives the wire id from the gateway trace id and the
// response leg. A trace spans one gateway request, so the id is stable for
// every block of the same response and distinct from SessionID, which spans
// the conversation. Without a trace the caller's own correlation handle stands
// in, and when that is empty too the id is empty: an empty id on the wire is
// not a missing id, it is a shared one, and the engine would correlate every
// stream in the process into a single bucket.
func segmentStreamID(traceID string, seg appplugins.StreamSegment) string {
	if traceID != "" {
		return traceID + streamIDSeparator + legResponse
	}
	if strings.TrimSpace(seg.StreamID) == "" {
		return ""
	}
	return seg.StreamID
}

// segmentPayload reuses the framing the buffered response leg gives a whole
// completion, so a partial assistant turn and a complete one differ only in
// how much text they carry.
//
// tools[] is omitted until the final block. indirect_prompt_injection scores
// role=tool content and tools[] descriptions only, and llmResponsePayload
// forwards the request's tools on the output leg, so a tool description that
// trips it would produce one identical finding per block: a cascade in enforce
// mode, and one malicious strike per block in alert-only.
func (p *Plugin) segmentPayload(
	ctx context.Context,
	in appplugins.ExecInput,
	seg appplugins.StreamSegment,
) (json.RawMessage, bool) {
	cresp := &adapter.CanonicalResponse{
		Content:   seg.Accumulated,
		ToolCalls: seg.ToolCalls,
	}
	if strings.TrimSpace(seg.Reasoning) != "" {
		cresp.Reasoning = &adapter.CanonicalReasoning{ThinkingText: seg.Reasoning}
	}
	// Same asymmetry the buffered leg carries: a block whose text is still
	// empty but which already holds a tool call or reasoning text is worth
	// inspecting, and neither of those can be rewritten in place. There
	// llmInspectionPayload leaves transformTarget.apply unset and a transform
	// degrades to a block; segmentVerdict reaches the same answer here.
	if !responseHasInspectableContent(cresp) {
		return nil, false
	}
	var tools []adapter.CanonicalTool
	if seg.Final {
		tools = p.requestTools(in.Request)
	}
	payload, err := llmResponsePayload(cresp, tools)
	if err != nil {
		p.warn(ctx, "trustguard stream segment payload build failed, skipping block",
			slog.String("plugin", PluginName),
			slog.Int("seq", seg.Seq),
			slog.Any("error", err),
		)
		return nil, false
	}
	return payload, true
}

func (p *Plugin) requestTools(req *infracontext.RequestContext) []adapter.CanonicalTool {
	if req == nil {
		return nil
	}
	format, err := adapter.ResolveAgentFormat(req.Provider, req.SourceFormat, nil)
	if err != nil {
		return nil
	}
	request, err := p.registry.DecodeRequestFor(req.Body, format)
	if err != nil || request == nil {
		return nil
	}
	return request.Tools
}

func segmentVerdict(seg appplugins.StreamSegment, resp *GuardResponse) *appplugins.SegmentVerdict {
	switch resp.Status {
	case statusTransform:
		// A transform replaces the whole accumulated buffer. With nothing
		// accumulated the flagged content is a tool call or reasoning text,
		// which the buffer does not carry: applying the mask would neither
		// remove the flagged bytes nor leave them where they were, it would
		// inject assistant text where a tool call or a thought stood. Execute
		// refuses the same response through reasonTransformUnsupported.
		if strings.TrimSpace(seg.Accumulated) == "" {
			return segmentBlock(typeBlocked, clientBlockMessage(resp))
		}
		masked, ok := transformedInput(resp.TransformedPayload)
		if !ok {
			return segmentBlock(typeBlocked, clientBlockMessage(resp))
		}
		return &appplugins.SegmentVerdict{HasTransform: true, Transformed: masked}
	case statusBlock, statusAsk:
		return segmentBlock(typeBlocked, clientBlockMessage(resp))
	default:
		return segmentAllow()
	}
}

func segmentAllow() *appplugins.SegmentVerdict {
	return &appplugins.SegmentVerdict{}
}

func segmentBlock(kind, message string) *appplugins.SegmentVerdict {
	return &appplugins.SegmentVerdict{Block: true, Type: kind, Message: message}
}
