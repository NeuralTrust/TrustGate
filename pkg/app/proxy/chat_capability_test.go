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
	"errors"
	"testing"
	"time"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type capabilityCatalog struct {
	listed map[string]appcatalog.Verdict
	caps   map[string]map[string]any
}

func (c capabilityCatalog) Lists(_ context.Context, provider, model string) appcatalog.Verdict {
	if c.listed == nil {
		return appcatalog.VerdictUnknown
	}
	if verdict, ok := c.listed[provider+":"+model]; ok {
		return verdict
	}
	return appcatalog.VerdictUnknown
}

func (c capabilityCatalog) Capabilities(_ context.Context, provider, model string) (map[string]any, bool) {
	flags, ok := c.caps[provider+":"+model]
	if !ok || len(flags) == 0 {
		return nil, false
	}
	return flags, true
}

func (capabilityCatalog) InvalidateCache() {}

func newTestForwarderWithListing(t *testing.T, invoker appproxy.ProviderInvoker, listing appcatalog.ModelListing) appproxy.Forwarder {
	t.Helper()
	mgr := cache.NewTTLMapManager(time.Minute)
	return appproxy.NewForwarder(
		loadbalancer.NewBaseFactory(nil, nil, nil, nil, nil),
		newPermissiveCache(t), mgr, invoker, nil, nil, approuting.NewResolver(), listing, nil, nil, newTestLogger(),
	)
}

func chatRequest(model, capability string) *infracontext.RequestContext {
	return &infracontext.RequestContext{
		Body:            []byte(`{"model":"` + model + `","messages":[{"role":"user","content":"Hello"}]}`),
		ProxyCapability: capability,
	}
}

func TestForward_ChatRejectsKnownNonChatModel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		model string
		key   string
	}{
		{name: "embedding model", model: "text-embedding-3-small", key: "embed"},
		{name: "image model", model: "gpt-image-1.5", key: "image"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gatewayID := ids.New[ids.GatewayKind]()
			openai := backendFor(gatewayID, "openai")
			anthropic := backendFor(gatewayID, "anthropic")
			rc := routableConsumerWith(gatewayID, openai, anthropic)
			rc.Consumer.Fallback = enabledFallback(openai.ID, anthropic.ID)

			invoker := proxymocks.NewProviderInvoker(t)
			fwd := newTestForwarderWithListing(t, invoker, capabilityCatalog{
				listed: map[string]appcatalog.Verdict{
					"openai:" + tc.model:    appcatalog.VerdictListed,
					"anthropic:" + tc.model: appcatalog.VerdictAbsent,
				},
				caps: map[string]map[string]any{
					"openai:" + tc.model: {tc.key: true},
				},
			})
			_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
				GatewayID: gatewayID,
				Consumer:  rc,
				Request:   chatRequest(tc.model, "chat"),
			})
			require.ErrorIs(t, err, appproxy.ErrModelNotChatCapable)
			require.EqualError(t, err, "model does not support chat completions: "+tc.model)
		})
	}
}

func TestForward_ChatAllowsChatAndUnknownCapabilities(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, openai)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool {
			return bk.ID == openai.ID
		}), mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte(`{"ok":true}`)}, nil).
		Twice()

	listing := capabilityCatalog{
		listed: map[string]appcatalog.Verdict{
			"openai:gpt-4.1":      appcatalog.VerdictListed,
			"openai:legacy-model": appcatalog.VerdictListed,
		},
		caps: map[string]map[string]any{
			"openai:gpt-4.1": {"chat": true},
		},
	}
	fwd := newTestForwarderWithListing(t, invoker, listing)

	for _, model := range []string{"gpt-4.1", "legacy-model"} {
		res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
			GatewayID: gatewayID,
			Consumer:  rc,
			Request:   chatRequest(model, "chat"),
		})
		require.NoError(t, err)
		require.Equal(t, 200, res.StatusCode)
	}
}

func TestForward_EmbeddingsStillReachAnEmbeddingModel(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	anthropic := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, openai, anthropic)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool {
			return bk.ID == openai.ID
		}), mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte(`{"data":[]}`)}, nil).
		Once()

	fwd := newTestForwarderWithListing(t, invoker, capabilityCatalog{
		caps: map[string]map[string]any{
			"openai:text-embedding-3-small": {"embed": true},
		},
	})
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   chatRequest("text-embedding-3-small", "embeddings"),
	})
	require.NoError(t, err)
	require.Equal(t, 200, res.StatusCode)
}

func TestForward_PinnedNonChatModelDoesNotHop(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	anthropic := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, openai, anthropic)
	rc.Consumer.Fallback = enabledFallback(anthropic.ID)

	fwd := newTestForwarderWithListing(t, proxymocks.NewProviderInvoker(t), capabilityCatalog{
		caps: map[string]map[string]any{
			"openai:text-embedding-3-small": {"embed": true},
			"anthropic:claude-sonnet-4":     {"chat": true},
		},
	})
	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   chatRequest("@openai/text-embedding-3-small", "chat"),
	})
	require.ErrorIs(t, err, appproxy.ErrModelNotChatCapable)
	require.False(t, errors.Is(err, appproxy.ErrCapabilityNotSupported))
}
