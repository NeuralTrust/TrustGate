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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/pluginutiltest"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// The image, audio and file routes carry no chat, so TrustGuard records the same
// skip the other external guardrails do and sends nothing.
func TestNonChatRoutesAreSkippedWithTheSharedReason(t *testing.T) {
	t.Parallel()
	for _, tc := range pluginutiltest.NonChatRoutes(t) {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			p := newTestPlugin(t, adapter.NewRegistry(), "")
			req := requestContext()
			req.Body = tc.Body
			req.SourceFormat = tc.Format
			req.ProxyCapability = tc.Capability
			event, span := newEvent()
			in := execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil, event)

			_, _, halt := p.llmInspectionPayload(context.Background(), in, directionInput)
			require.NotNil(t, halt)
			assert.NoError(t, halt.err)
			skipped, reason := pluginutiltest.SkipOf(t, span.PluginAttrsCopy().Extras)
			assert.True(t, skipped)
			assert.Equal(t, pluginutil.SkipReasonNonChatRoute, reason)
		})
	}
}

func TestAnUndecodableResponseIsSkippedWithTheSharedReason(t *testing.T) {
	t.Parallel()
	for _, tc := range pluginutiltest.UninspectableResponses() {
		if tc.SkipReason != pluginutil.SkipReasonUndecodableResponse {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			p := newTestPlugin(t, adapter.NewRegistry(), "")
			req := requestContext()
			req.SourceFormat = tc.Format
			event, span := newEvent()
			in := execInputWithEvent(policy.StagePreResponse, policy.ModeEnforce, settings(""), req,
				&infracontext.ResponseContext{StatusCode: tc.Status, Body: tc.Body}, event)

			_, _, halt := p.llmInspectionPayload(context.Background(), in, directionOutput)
			require.NotNil(t, halt)
			skipped, reason := pluginutiltest.SkipOf(t, span.PluginAttrsCopy().Extras)
			assert.True(t, skipped)
			assert.Equal(t, pluginutil.SkipReasonUndecodableResponse, reason)
		})
	}
}
