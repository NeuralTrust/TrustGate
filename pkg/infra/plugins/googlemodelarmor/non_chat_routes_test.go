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

package googlemodelarmor

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/pluginutiltest"
)

// The routes a policy covers include the ones that carry no chat messages:
// image generation, audio and files. Their bodies are not chat JSON, so there is
// no text for the guardrail to judge: that is the route's shape, not anything
// the client got wrong, so the leg is a recorded skip and never a refusal.
func TestNonChatRoutesAreSkippedNotRefused(t *testing.T) {
	t.Parallel()
	for _, tc := range pluginutiltest.NonChatRoutes(t) {
		for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
			t.Run(tc.Name+" "+string(mode), func(t *testing.T) {
				t.Parallel()
				stub := newModelArmorStub(t, http.StatusOK, allowResponse)
				p := pluginWithStub(stub)
				req := reqCtx(tc.Body)
				req.SourceFormat = tc.Format
				req.ProxyCapability = tc.Capability
				event, span := newStreamEvent()
				in := execInput(policy.StagePreRequest, mode, modelArmorSettings(), req, nil)
				in.Event = event

				res, err := p.Execute(context.Background(), in)
				assertPassThrough(t, res, err)
				assert.Zero(t, stub.count())
				skipped, reason := pluginutiltest.SkipOf(t, span.PluginAttrsCopy().Extras)
				assert.True(t, skipped)
				assert.Equal(t, pluginutil.SkipReasonNoInspectableInput, reason)
			})
		}
	}
}

func TestMalformedChatBodyStillBlocksOnAChatRoute(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, allowResponse)
	p := pluginWithStub(stub)
	req := reqCtx(pluginutiltest.MalformedChatBody)
	req.ProxyCapability = "chat"
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), req, nil)

	_, err := p.Execute(context.Background(), in)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
	assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
}

// pre_response also runs on what the upstream answered when it did not produce
// a completion: an error page from a proxy in front of it, a provider error
// envelope, or audio bytes. None of those is content the client steered into
// the guardrail, so each is a recorded skip and never a refusal.
func TestUninspectableResponsesAreSkippedNotRefused(t *testing.T) {
	t.Parallel()
	for _, tc := range pluginutiltest.UninspectableResponses() {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			stub := newModelArmorStub(t, http.StatusOK, allowResponse)
			p := pluginWithStub(stub)
			req := reqCtx(openAIRequest())
			req.SourceFormat = tc.Format
			event, span := newStreamEvent()
			in := execInput(policy.StagePreResponse, policy.ModeEnforce, modelArmorSettings(), req,
				&infracontext.ResponseContext{StatusCode: tc.Status, Body: tc.Body})
			in.Event = event

			res, err := p.Execute(context.Background(), in)
			assertPassThrough(t, res, err)
			assert.Zero(t, stub.count())
			skipped, reason := pluginutiltest.SkipOf(t, span.PluginAttrsCopy().Extras)
			assert.True(t, skipped)
			assert.Equal(t, tc.SkipReason, reason)
		})
	}
}

// A chat route whose format has no adapter is the gateway's own gap: it is
// config_invalid/unsupported_format and fails open, not a skip made for a route
// that carries no chat.
func TestChatRouteWithoutAnAdapterIsConfigInvalidNotASkip(t *testing.T) {
	t.Parallel()
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			stub := newModelArmorStub(t, http.StatusOK, allowResponse)
			p := pluginWithStub(stub)
			req := reqCtx(openAIRequest())
			req.SourceFormat = "no_such_format"
			req.ProxyCapability = "chat"
			event, span := newStreamEvent()
			in := execInput(policy.StagePreRequest, mode, modelArmorSettings(), req, nil)
			in.Event = event

			res, err := p.Execute(context.Background(), in)
			assertPassThrough(t, res, err)
			assert.Zero(t, stub.count())
			skipped, _ := pluginutiltest.SkipOf(t, span.PluginAttrsCopy().Extras)
			assert.False(t, skipped)
			reason, detail := pluginutiltest.FailureOf(t, span.PluginAttrsCopy().Extras)
			assert.Equal(t, string(appplugins.FailureConfigInvalid), reason)
			assert.Equal(t, appplugins.DetailUnsupportedFormat, detail)
		})
	}
}
