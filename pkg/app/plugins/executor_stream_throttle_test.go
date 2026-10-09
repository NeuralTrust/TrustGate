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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// A throttle is the provider's quota, which concurrent traffic can exhaust: it
// never extends the retirement streak, or a client could have an entry switched
// off for the rest of its stream by sending traffic that throttles the account.
func TestRunStreamSegment_ThrottledBlocksDoNotRetireTheEntry(t *testing.T) {
	t.Parallel()
	exec, pols, inspectors := streamChain(t, entrySpec{slug: "guard", mode: policy.ModeObserve})
	runner, ok := exec.(*executor)
	require.True(t, ok)
	in := failureInput(pols)
	ctx, _, publish := failureStreamCtx(t)
	defer publish()
	inspectors["guard"].err = WrapExternalStreamFailure("stub", FailureTransport, "throttled", errors.New("ThrottlingException"))

	for i := 1; i <= streamEntryRetireAfter+2; i++ {
		_, err := runner.RunStreamSegment(ctx, in, segment(i, false))
		require.NoError(t, err)
	}
	assert.Len(t, inspectors["guard"].seen, streamEntryRetireAfter+2, "a throttled entry is called again on every block")
}
