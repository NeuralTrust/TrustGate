// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bedrockguardrail

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// The pieces of a streamed block are spaced at the policy's region floor, by a
// spacer of their own for each block, and a throttle on one is other traffic.
func TestStreamPiecesAreSpacedAtTheRegionFloorPerBlock(t *testing.T) {
	t.Parallel()
	p := pluginOver(&latencyGuardrail{})
	in := execInput(policy.StagePreResponse, policy.ModeEnforce, settingsIn("eu-west-3"), nil, nil)

	wait := p.SpaceStreamPieces(in)
	require.NotNil(t, wait)
	started := time.Now()
	for range 4 {
		require.NoError(t, wait(context.Background(), maxStreamWindowBytes))
	}
	assert.Greater(t, time.Since(started), 250*time.Millisecond, "four pieces of 9 units exceed the 25-unit burst, so the last waits for the refill")

	other := p.SpaceStreamPieces(in)
	started = time.Now()
	require.NoError(t, other(context.Background(), maxStreamWindowBytes))
	assert.Less(t, time.Since(started), 100*time.Millisecond, "a new block starts with a full burst")

	assert.True(t, p.StreamThrottleIsOtherTraffic())
	assert.Equal(t, streamingDefaults.GuardTimeout, p.StreamGuardTimeout())
	var _ appplugins.StreamPieceSpacing = p
}

func TestStreamPieceSpacingEndsWithTheBlocksDeadline(t *testing.T) {
	t.Parallel()
	p := pluginOver(&latencyGuardrail{})
	wait := p.SpaceStreamPieces(execInput(policy.StagePreResponse, policy.ModeEnforce, settingsIn("eu-west-3"), nil, nil))
	require.NoError(t, wait(context.Background(), 25000))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := wait(ctx, 25000)

	require.ErrorIs(t, err, context.DeadlineExceeded)
}
