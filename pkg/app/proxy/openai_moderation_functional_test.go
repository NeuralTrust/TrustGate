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

package proxy_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/openaimoderation"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const moderationTestTimeout = 5 * time.Second

func moderationServer(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/moderations", r.URL.Path)
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func moderationPolicy(mode policy.Mode) *policy.Policy {
	return &policy.Policy{
		ID:       ids.New[ids.PolicyKind](),
		Name:     "moderation",
		Slug:     openaimoderation.PluginName,
		Enabled:  true,
		Priority: 1,
		Stages:   []policy.Stage{policy.StagePreRequest},
		Mode:     mode,
		Settings: map[string]any{
			"api_key":    "test-key",
			"thresholds": map[string]any{"hate": 0.7},
		},
	}
}

func moderationRequest() *infracontext.RequestContext {
	return &infracontext.RequestContext{
		Context:      context.Background(),
		SourceFormat: "openai",
		Body:         []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"i hate you"}]}`),
	}
}

const flaggedModerationBody = `{"id":"modr-1","model":"omni-moderation-latest","results":[{"flagged":true,"categories":{"hate":true},"category_scores":{"hate":0.91}}]}`

const cleanModerationBody = `{"id":"modr-2","model":"omni-moderation-latest","results":[{"flagged":false,"categories":{"hate":false},"category_scores":{"hate":0.02}}]}`

func TestForward_OpenAIModerationEnforceBlocks(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)
	rc.Policies = []*policy.Policy{moderationPolicy(policy.ModeEnforce)}

	url := moderationServer(t, flaggedModerationBody)
	plugin := openaimoderation.New(adapter.NewRegistry(), url, moderationTestTimeout, newTestLogger())

	invoker := proxymocks.NewProviderInvoker(t)

	fwd := forwarderWithPlugin(t, invoker, plugin)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   moderationRequest(),
	})

	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
	assert.Contains(t, string(res.Body), "content_flagged")
	assert.Contains(t, string(res.Body), "hate")
}

func TestForward_OpenAIModerationObservePassesThrough(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)
	rc.Policies = []*policy.Policy{moderationPolicy(policy.ModeObserve)}

	url := moderationServer(t, flaggedModerationBody)
	plugin := openaimoderation.New(adapter.NewRegistry(), url, moderationTestTimeout, newTestLogger())

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	fwd := forwarderWithPlugin(t, invoker, plugin)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   moderationRequest(),
	})

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "ok", string(res.Body))
}

func TestForward_OpenAIModerationAllowsCleanContent(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, bk)
	rc.Policies = []*policy.Policy{moderationPolicy(policy.ModeEnforce)}

	url := moderationServer(t, cleanModerationBody)
	plugin := openaimoderation.New(adapter.NewRegistry(), url, moderationTestTimeout, newTestLogger())

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	fwd := forwarderWithPlugin(t, invoker, plugin)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   moderationRequest(),
	})

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "ok", string(res.Body))
}
