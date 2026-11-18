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

package mcp

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/stretchr/testify/require"
)

type holdingExecutor struct {
	released   atomic.Int32
	atResponse int32
	fail       error
}

func (e *holdingExecutor) RunStage(ctx context.Context, in appplugins.StageInput) (*appplugins.StageOutcome, error) {
	if in.Stage == "pre_request" {
		done := appplugins.RequestDoneFrom(ctx)
		if done == nil || !done.OnDone(func() { e.released.Add(1) }) {
			return nil, context.Canceled
		}
		return &appplugins.StageOutcome{}, nil
	}
	e.atResponse = e.released.Load()
	return &appplugins.StageOutcome{}, e.fail
}

func TestRPCDispatcher_CallTool_FreesPluginHoldWhenTheCallEnds(t *testing.T) {
	tests := []struct {
		name string
		fail error
	}{
		{name: "answered"},
		{name: "response stage fails", fail: context.DeadlineExceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newBenchFixture(t, benchNoScope)
			exec := &holdingExecutor{fail: tt.fail}
			d := NewRPCDispatcher(
				&benchComposer{target: f.target, result: json.RawMessage(`{"content":[]}`)},
				NewPluginRunner(exec, discardLogger()),
				nil, nil, nil,
			)

			_, _ = d.Dispatch(f.ctx(), f.rc, "", "tools/call", json.RawMessage(`{"name":"run_query","arguments":{}}`))

			require.Zero(t, exec.atResponse, "released while the call was still running")
			require.EqualValues(t, 1, exec.released.Load())
		})
	}
}
