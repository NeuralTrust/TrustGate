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

package a2a_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/stretchr/testify/require"
)

func TestExchange_FreesPluginHoldWhenTheCallEnds(t *testing.T) {
	ag := newAgent(t, answer(readFixture(t, "v10.send.response.json")))
	var released atomic.Int32
	exec := func(ctx context.Context, in appplugins.StageInput) (*appplugins.StageOutcome, error) {
		if in.Stage == "pre_request" {
			require.True(t, appplugins.RequestDoneFrom(ctx).OnDone(func() { released.Add(1) }))
		}
		return &appplugins.StageOutcome{}, nil
	}
	h := newHarness(t, a2a.Version10, ag.URL, exec)
	body := readFixture(t, "v10.send.request.json")

	x, rpcErr := h.forwarder.Prepare(context.Background(), h.call(t, body, nil))
	require.Nil(t, rpcErr)
	require.Zero(t, released.Load(), "released before the call was sent")
	_, _ = x.Send(context.Background())

	require.EqualValues(t, 1, released.Load())
}

func TestExchange_FreesPluginHoldWhenAPluginBlocks(t *testing.T) {
	ag := newAgent(t, answer(nil))
	var released atomic.Int32
	exec := func(ctx context.Context, _ appplugins.StageInput) (*appplugins.StageOutcome, error) {
		require.True(t, appplugins.RequestDoneFrom(ctx).OnDone(func() { released.Add(1) }))
		return nil, &appplugins.PluginError{StatusCode: 429}
	}
	h := newHarness(t, a2a.Version10, ag.URL, exec)
	body := readFixture(t, "v10.send.request.json")

	_, rpcErr := h.forwarder.Prepare(context.Background(), h.call(t, body, nil))

	require.NotNil(t, rpcErr)
	require.EqualValues(t, 1, released.Load())
}

func TestStream_DiscardFreesPluginHold(t *testing.T) {
	ag, _ := sseAgent(t, fixtureEvents(t, "v10.stream.response.sse"), 0)
	var released atomic.Int32
	exec := func(ctx context.Context, in appplugins.StageInput) (*appplugins.StageOutcome, error) {
		if in.Stage == "pre_request" {
			require.True(t, appplugins.RequestDoneFrom(ctx).OnDone(func() { released.Add(1) }))
		}
		return &appplugins.StageOutcome{}, nil
	}
	h := newHarness(t, a2a.Version10, ag.URL, exec)
	s := openStream(t, h, streamRequest(a2a.Version10))
	require.Zero(t, released.Load())

	s.Discard()

	require.EqualValues(t, 1, released.Load())
}
