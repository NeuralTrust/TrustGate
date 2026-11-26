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
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/common/requestmeta"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const fakeUserToken = "test-user-token"

func userTokenRequest() (*infracontext.RequestContext, map[string][]string) {
	headers := map[string][]string{
		"x-neuraltrust-user-token": {" " + fakeUserToken + " "},
		"X-NeuralTrust-End-User":   {"someone-elses-id"},
		"User-Agent":               {"client/1.0"},
	}
	req := requestContext()
	req.Headers = headers
	return req, headers
}

func TestV2PluginForwardsTheUserTokenAsAssetsUserToken(t *testing.T) {
	t.Parallel()
	f := &fakeV2Engine{}
	p := newV2TestPlugin(t, newV2Engine(t, f).URL)
	req, headers := userTokenRequest()
	ctx := requestmeta.NewContext(context.Background(), "203.0.113.42", headers)
	// A declared end user is not an identity: it must still not reach the gate attributes.
	ctx = trace.NewContext(ctx, trace.New("t-1", trace.Metadata{GatewayID: "gw-test", EndUser: &trace.EndUser{ID: "someone-elses-id"}}))

	_, err := p.Execute(ctx, execInput(policy.StagePreRequest, policy.ModeEnforce, v2Settings(""), req, nil))
	require.NoError(t, err)

	seen := f.seen()
	require.Len(t, seen, 1)
	require.Zero(t, f.invalid)
	assert.Equal(t, map[string]any{"token": fakeUserToken}, seen[0].Assets["user"],
		"a token without a principal still sends the user: TrustGuard reads it from the claims")
	raw, err := json.Marshal(seen[0])
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "someone-elses-id", "the declared end user never reaches TrustGuard")
	require.NotNil(t, seen[0].OriginalRequest)
	assert.Equal(t, map[string][]string{"User-Agent": {"client/1.0"}}, seen[0].OriginalRequest.Headers,
		"the token header is not in original_request.headers")
}

func TestV2PluginUserTokenRidesWithThePrincipal(t *testing.T) {
	t.Parallel()
	f := &fakeV2Engine{}
	p := newV2TestPlugin(t, newV2Engine(t, f).URL)
	req, _ := userTokenRequest()
	rt := trace.New("t-1", trace.Metadata{GatewayID: "gw-test"})
	rt.SetPrincipalIdentity("svc-app", "api_key", "")
	ctx := trace.NewContext(context.Background(), rt)

	_, err := p.Execute(ctx, execInput(policy.StagePreRequest, policy.ModeEnforce, v2Settings(""), req, nil))
	require.NoError(t, err)

	seen := f.seen()
	require.Len(t, seen, 1)
	assert.Equal(t, map[string]any{"id": "svc-app", "auth_method": "api_key", "token": fakeUserToken}, seen[0].Assets["user"])
}

func TestV2PluginWithoutTheHeaderSendsNoUser(t *testing.T) {
	t.Parallel()
	f := &fakeV2Engine{}
	p := newV2TestPlugin(t, newV2Engine(t, f).URL)

	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, v2Settings(""), requestContext(), nil))
	require.NoError(t, err)
	seen := f.seen()
	require.Len(t, seen, 1)
	assert.NotContains(t, seen[0].Assets, "user")
}

func TestUserTokenOf(t *testing.T) {
	t.Parallel()
	with := func(v ...string) *infracontext.RequestContext {
		return &infracontext.RequestContext{Headers: map[string][]string{"X-Neuraltrust-User-Token": v}}
	}
	assert.Empty(t, userTokenOf(nil))
	assert.Empty(t, userTokenOf(&infracontext.RequestContext{}))
	assert.Empty(t, userTokenOf(with("", "  ")))
	assert.Empty(t, userTokenOf(with("a\r\nb")))
	assert.Empty(t, userTokenOf(with(string(make([]byte, maxUserTokenBytes+1)))))
	assert.Equal(t, fakeUserToken, userTokenOf(with("", fakeUserToken)))
}

// The v1 wire is byte-identical with or without the token, with or without a principal.
func TestV1RequestNeverCarriesTheUserToken(t *testing.T) {
	t.Parallel()
	for _, user := range []*GuardUser{nil, {ID: "u-1"}} {
		base := GuardRequest{
			Direction: directionInput, Protocol: protocolLLM, ConsumerID: "app-1",
			Attributes: GuardAttributes{ContentType: "text", User: user},
		}
		withToken := base
		withToken.UserToken = fakeUserToken
		want, err := marshalNoEscape(withInventory(base))
		require.NoError(t, err)
		got, err := marshalNoEscape(withInventory(withToken))
		require.NoError(t, err)
		assert.Equal(t, string(want), string(got))
		assert.NotContains(t, string(got), "token")
		if user == nil {
			assert.NotContains(t, string(got), `"user"`)
		}
	}
}

func TestV1PluginWithOnlyTheTokenHeaderSendsNoUser(t *testing.T) {
	t.Parallel()
	f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	req, _ := userTokenRequest()
	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil))
	require.NoError(t, err)
	f.mu.Lock()
	defer f.mu.Unlock()
	require.Equal(t, 1, f.hits)
	assert.Nil(t, f.lastBody.Attributes.User, "no user key at all on the v1 body")
}

func TestUserTokenOfIgnoresAnAmbiguousHeader(t *testing.T) {
	t.Parallel()
	req := &infracontext.RequestContext{Headers: map[string][]string{
		"X-Neuraltrust-User-Token": {"test-user-token"},
		"x-neuraltrust-user-token": {"test-other-token"},
	}}
	assert.Empty(t, userTokenOf(req))
	req = &infracontext.RequestContext{Headers: map[string][]string{"X-Neuraltrust-User-Token": {"test-user-token", "test-other-token"}}}
	assert.Empty(t, userTokenOf(req))
	req = &infracontext.RequestContext{Headers: map[string][]string{"X-Neuraltrust-User-Token": {"test-user-token", "test-user-token"}}}
	assert.Equal(t, fakeUserToken, userTokenOf(req))
}

// The header is client-controlled: TrustGuard refusing it must block under failure_mode=open, and must
// not be read as the gateway's own credential being rejected.
func TestV2PluginBlocksWhenTrustGuardRefusesTheUserToken(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		status int
		code   string
	}{
		{"invalid_401", http.StatusUnauthorized, "invalid_user_token"},
		{"required_403", http.StatusForbidden, "user_token_required"},
		{"not_configured_400", http.StatusBadRequest, "user_token_not_configured"},
		{"mismatch_403", http.StatusForbidden, "user_mismatch"},
		{"conflict_400", http.StatusBadRequest, "asset_conflict"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeV2Engine{status: c.status, raw: `{"code":"` + c.code + `","error":"x"}`}
			p := newV2TestPlugin(t, newV2Engine(t, f).URL)
			req, _ := userTokenRequest()
			settings := v2Settings("")
			settings["failure_mode"] = "open"

			res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings, req, nil))
			assert.Nil(t, res)
			pe, ok := appplugins.AsPluginError(err)
			require.True(t, ok, "got %v", err)
			assert.Equal(t, http.StatusForbidden, pe.StatusCode)
			assert.Equal(t, typeUserTokenRefused, pe.Type)
			assert.Contains(t, string(pe.Body), c.code)
			assert.Len(t, f.tokenRequests(), 1, "the service token is not invalidated nor refetched")
			assert.Equal(t, int32(1), atomic.LoadInt32(&f.evaluateCalls), "no retry")
		})
	}
}

func TestV2PluginUserTokenUnavailableStaysAvailability(t *testing.T) {
	t.Parallel()
	f := &fakeV2Engine{status: http.StatusServiceUnavailable, raw: `{"code":"user_token_unavailable"}`}
	p := newV2TestPlugin(t, newV2Engine(t, f).URL)
	req, _ := userTokenRequest()
	settings := v2Settings("")
	settings["failure_mode"] = "open"
	res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings, req, nil))
	require.NoError(t, err)
	require.NotNil(t, res)
}

func TestUserTokenRefusalOfLeavesOtherAnswersAlone(t *testing.T) {
	t.Parallel()
	assert.Nil(t, userTokenRefusalOf(http.StatusUnauthorized, []byte(`{"error":"expired"}`), true), "a 401 without a code is the service token")
	assert.Nil(t, userTokenRefusalOf(http.StatusForbidden, []byte(`{}`), false), "a 403 without a user token stays the service's")
	assert.NotNil(t, userTokenRefusalOf(http.StatusForbidden, []byte(`{}`), true))
	assert.Nil(t, userTokenRefusalOf(http.StatusServiceUnavailable, []byte(`{"code":"user_token_unavailable"}`), true))
}

func TestStreamSegmentV1WithOnlyTheTokenHeaderSendsNoUser(t *testing.T) {
	t.Parallel()
	g := &segmentGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
	req, _ := userTokenRequest()
	req.Body = segmentRequest().Body
	in := execInput(policy.StagePreResponse, policy.ModeEnforce, streamingSettings(nil), req, nil)

	_, err := p.InspectSegment(segmentTraceContext(), in, appplugins.StreamSegment{Seq: 1, Accumulated: "hi"})
	require.NoError(t, err)
	calls := g.calls()
	require.Len(t, calls, 1)
	assert.Nil(t, calls[0].Attributes.User, "no user key at all on the v1 body")
}

func TestSegmentFailureBlocksOnAUserTokenRefusal(t *testing.T) {
	t.Parallel()
	p := newV2TestPlugin(t, "http://unused")
	in := execInput(policy.StagePreResponse, policy.ModeEnforce, streamingSettings(nil), requestContext(), nil)
	verdict, err := p.segmentFailure(context.Background(), in, Settings{}, appplugins.StreamSegment{Seq: 1},
		&userTokenRefusedError{status: http.StatusUnauthorized, code: "invalid_user_token"})
	require.NoError(t, err)
	require.NotNil(t, verdict)
	assert.True(t, verdict.Block)
	assert.Equal(t, http.StatusForbidden, verdict.StatusCode)
}
