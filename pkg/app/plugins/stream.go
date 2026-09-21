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

package plugins

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// StreamSegment is one closed block of a streaming response, handed to a
// StreamInspector for a verdict. Accumulated is a contiguous prefix of the text
// the provider has produced, never of the text already released to the client:
// building it from released text would hide a finding split across the block in
// flight and the one being inspected. Text is the delta of this block alone;
// Reasoning and ToolCalls are cumulative like Accumulated, not per-block
// deltas. Truncated says the guard hit its accumulation cap and swapped
// Accumulated from a full prefix to a tail window, so the plugin can carry the
// distinction onto the wire envelope the engine reads.
type StreamSegment struct {
	StreamID    string
	Seq         int
	Final       bool
	Truncated   bool
	Text        string
	Accumulated string
	Reasoning   string
	ToolCalls   []adapter.CanonicalToolCall
}

// SegmentVerdict is a plugin's answer for one StreamSegment. Transformed, when
// HasTransform is set, replaces the whole of StreamSegment.Accumulated: the
// caller owns a single contiguous buffer and rewrites it in place, so splicing
// per-segment fragments back together is never required.
type SegmentVerdict struct {
	Block        bool
	Type         string
	Message      string
	HasTransform bool
	Transformed  string
	Fingerprints []string
}

// StreamInspector is the opt-in a plugin declares to be consulted per block of
// a streaming response. A plugin that does not implement it is absent from the
// stream chain and still runs at the fixed stages, so the capability extends
// one plugin at a time, the way ScopeInertSafe does.
type StreamInspector interface {
	InspectSegment(ctx context.Context, in ExecInput, seg StreamSegment) (*SegmentVerdict, error)
}

// SegmentOutcome is the executor's consolidated answer across the chain for one
// StreamSegment.
type SegmentOutcome struct {
	Block        bool
	Type         string
	Message      string
	HasTransform bool
	Transformed  string
	Fingerprints []string
}

// streamInspector reports whether the descriptor opted in. A descriptor that
// does not implement StreamInspector is denied, so no plugin joins the stream
// chain by omission.
func streamInspector(d PluginDescriptor) bool {
	_, ok := d.(StreamInspector)
	return ok
}
