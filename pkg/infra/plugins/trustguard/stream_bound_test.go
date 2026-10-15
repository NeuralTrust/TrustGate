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
package trustguard

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// The stream executor splits a block that is larger than an entry's window for
// every inspector except one that declares it bounds its own payload. TrustGuard
// is that: it is one evaluation of the whole block, so a split would count the
// block once per piece and send the end of the response more than once.
func TestTheStreamExecutorNeverSplitsABlockForTrustGuard(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "http://guard.local", time.Second, "id", "secret", nil)

	bound, ok := any(p).(appplugins.StreamPayloadBound)

	assert.True(t, ok)
	assert.True(t, bound.BoundsStreamPayload())
}
