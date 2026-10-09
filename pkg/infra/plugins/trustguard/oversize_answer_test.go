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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// An answer above what the call could faithfully echo is the request's: the
// gateway reads at most twice the payload it sent plus a slack, and an answer
// beyond that is not the payload coming back. Letting it through as an outage
// would hand the client a way to have its email forwarded unmasked, so a
// blocking mode refuses it.
func TestAnAnswerAboveTheLimitIsInput(t *testing.T) {
	t.Parallel()

	text := "reach me at victim@example.com"
	raw, err := json.Marshal(map[string]any{"model": "gpt-4o", "messages": []map[string]string{{"role": "user", "content": text}}})
	require.NoError(t, err)
	req := requestContext()
	req.Body = raw

	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{echoMask: func(string) string { return strings.Repeat("x", 2*maxResponseBytes) }}
			p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
			event, span := newEvent()
			res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, mode, settings(""), req, nil, event))

			extras, ok := span.PluginAttrsCopy().Extras.(guardData)
			require.True(t, ok)
			assert.Equal(t, "input", extras.FailureClass, "reason %q", extras.FailureReason)
			if mode == policy.ModeEnforce {
				pe, isPE := appplugins.AsPluginError(err)
				require.True(t, isPE, "want a refusal, got res=%v err=%v", res, err)
				assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, decisionFailedOpen, extras.Decision)
		})
	}
}
