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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/common/requestmeta"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
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

// The v1 wire never carries the token.
func TestV1RequestNeverCarriesTheUserToken(t *testing.T) {
	t.Parallel()
	body := GuardRequest{
		Direction: directionInput, Protocol: protocolLLM, ConsumerID: "app-1",
		Attributes: GuardAttributes{ContentType: "text", User: &GuardUser{ID: "u-1", Token: fakeUserToken}},
	}
	raw, err := marshalNoEscape(withInventory(body))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), fakeUserToken)
	assert.NotContains(t, string(raw), "token")
}
