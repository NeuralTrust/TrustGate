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

// The mask echoes the text back in the answer's JSON, where '<' is written as
// <: a text of angle brackets comes back six times its size, and the
// client chose that. The answer outgrowing the limit is therefore the request's
// doing, and a blocking mode refuses it instead of forwarding the unmasked
// original as if TrustGuard were down.
func TestAnAnswerAboveTheLimitOnAPaddedTextIsInput(t *testing.T) {
	t.Parallel()

	text := strings.Repeat("<", 180<<10) + " victim@example.com"
	raw, err := json.Marshal(map[string]any{"model": "gpt-4o", "messages": []map[string]string{{"role": "user", "content": text}}})
	require.NoError(t, err)
	req := requestContext()
	req.Body = raw

	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{echoMask: func(s string) string { return strings.ReplaceAll(s, "victim@example.com", "[EMAIL]") }}
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
