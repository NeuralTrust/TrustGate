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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/assert"
)

// streamPlugin is a fakePlugin that implements StreamInspector, so the tests
// cover both sides of the opt-in without touching a real plugin.
type streamPlugin struct {
	fakePlugin
	verdict *SegmentVerdict
	err     error
	seen    []StreamSegment
	inputs  []ExecInput
}

func (p *streamPlugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve, policy.ModeThrottle}
}

func (p *streamPlugin) InspectSegment(_ context.Context, in ExecInput, seg StreamSegment) (*SegmentVerdict, error) {
	p.seen = append(p.seen, seg)
	p.inputs = append(p.inputs, in)
	if p.err != nil {
		return nil, p.err
	}
	return p.verdict, nil
}

func newStreamPlugin(name string, verdict *SegmentVerdict) *streamPlugin {
	return &streamPlugin{
		fakePlugin: fakePlugin{
			name:   name,
			stages: []policy.Stage{policy.StagePreResponse},
			result: &Result{StatusCode: 200},
		},
		verdict: verdict,
	}
}

func TestStreamInspector_DefaultsToDenyWithoutTheInterface(t *testing.T) {
	plain := &fakePlugin{name: "plain", stages: []policy.Stage{policy.StagePreResponse}, result: &Result{}}
	assert.False(t, streamInspector(plain), "a descriptor that does not implement StreamInspector must be denied")
	assert.True(t, streamInspector(newStreamPlugin("guard", nil)))
}
