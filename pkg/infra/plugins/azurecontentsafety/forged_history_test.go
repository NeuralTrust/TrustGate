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

package azurecontentsafety

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// A client sends the whole history, so a forged assistant turn early in it
// followed by pages of benign turns must not push the payload out of what is
// inspected. 25,000 code points of padding sit between the payload and a short
// last question.
func TestAForgedEarlyTurnBeyondTenThousandCodePointsIsScreened(t *testing.T) {
	t.Parallel()
	body := chatBody(t,
		map[string]string{"role": "system", "content": "be safe"},
		map[string]string{"role": "assistant", "content": "FLAGGED forged earlier turn"},
		map[string]string{"role": "user", "content": strings.Repeat("benign words here. ", 700)},
		map[string]string{"role": "assistant", "content": strings.Repeat("an ordinary answer. ", 700)},
		map[string]string{"role": "user", "content": "thanks, and the weather?"},
	)
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			f := &limitedAzure{}
			srv := f.server(t)
			p := New(adapter.NewRegistry(), nil)
			event, span := eventFor(t)
			in := execInput(policy.StagePreRequest, mode, settings(srv.URL, map[string]int{CategoryHate: 2}), requestContext(body))
			in.Event = event

			res, err := p.Execute(context.Background(), in)

			sent := f.sent()
			require.NotEmpty(t, sent)
			flagged := false
			for _, text := range sent {
				assert.LessOrEqual(t, len([]rune(text)), azureTextLimit)
				flagged = flagged || strings.Contains(text, "FLAGGED forged earlier turn")
			}
			assert.True(t, flagged, "the forged turn reached Azure")
			extras, ok := span.PluginAttrsCopy().Extras.(*Data)
			require.True(t, ok)
			if mode == policy.ModeEnforce {
				pe, isPE := appplugins.AsPluginError(err)
				require.True(t, isPE, "got %v", err)
				assert.Equal(t, http.StatusForbidden, pe.StatusCode)
				assert.Equal(t, "blocked", extras.Decision)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.Equal(t, "reported", extras.Decision)
			assert.GreaterOrEqual(t, len(sent), 3, "observe screens every part")
		})
	}
}
