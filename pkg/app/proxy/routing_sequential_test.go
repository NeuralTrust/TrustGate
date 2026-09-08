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
	"fmt"
	"testing"
	"time"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type stubListing struct {
	verdicts map[string]appcatalog.Verdict
}

func (s stubListing) Lists(_ context.Context, providerCode, model string) appcatalog.Verdict {
	if verdict, ok := s.verdicts[providerCode+":"+model]; ok {
		return verdict
	}
	return appcatalog.VerdictUnknown
}

func (s stubListing) InvalidateCache() {}

func newSequentialForwarder(
	t *testing.T,
	invoker appproxy.ProviderInvoker,
	listing appcatalog.ModelListing,
) appproxy.Forwarder {
	t.Helper()
	mgr := cache.NewTTLMapManager(time.Minute)
	return appproxy.NewForwarder(
		loadbalancer.NewBaseFactory(nil, nil, nil, nil),
		newPermissiveCache(t), mgr, invoker, nil, nil,
		approuting.NewResolver(), listing, nil, nil, newTestLogger(),
	)
}

func chatBody(model string) []byte {
	return []byte(fmt.Sprintf(`{"model":%q,"messages":[]}`, model))
}

func modelNotFoundBody(provider string) []byte {
	return []byte(fmt.Sprintf(
		`{"error":{"message":"The model does not exist or you do not have access to it (%s)",`+
			`"type":"invalid_request_error","code":"model_not_found"}}`, provider))
}

func invocationRecorder(t *testing.T, respond func(provider string) (*appproxy.ProviderResponse, error)) (
	*proxymocks.ProviderInvoker, *[]string,
) {
	t.Helper()
	invoked := make([]string, 0, 4)
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(
			_ context.Context,
			bk *registrydomain.Registry,
			_ *infracontext.RequestContext,
		) (*appproxy.ProviderResponse, error) {
			invoked = append(invoked, bk.Provider())
			return respond(bk.Provider())
		}).
		Maybe()
	return invoker, &invoked
}

func TestForward_SequentialChain_UnqualifiedModelPicksTheRegistryThatServesIt(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bedrock := backendFor(gatewayID, "bedrock")
	openai := backendFor(gatewayID, "openai")
	vertex := backendFor(gatewayID, "vertex")
	rc := routableConsumerWith(gatewayID, bedrock, openai, vertex)

	listing := stubListing{verdicts: map[string]appcatalog.Verdict{
		"bedrock:gemini-3-flash-preview": appcatalog.VerdictAbsent,
		"openai:gemini-3-flash-preview":  appcatalog.VerdictAbsent,
		"vertex:gemini-3-flash-preview":  appcatalog.VerdictListed,
		"bedrock:gpt-4.1":                appcatalog.VerdictAbsent,
		"openai:gpt-4.1":                 appcatalog.VerdictListed,
		"vertex:gpt-4.1":                 appcatalog.VerdictAbsent,
	}}

	for _, tc := range []struct {
		model string
		want  string
	}{
		{model: "gemini-3-flash-preview", want: "vertex"},
		{model: "gpt-4.1", want: "openai"},
	} {
		t.Run(tc.model, func(t *testing.T) {
			invoker, invoked := invocationRecorder(t, func(string) (*appproxy.ProviderResponse, error) {
				return &appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil
			})
			fwd := newSequentialForwarder(t, invoker, listing)

			res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
				GatewayID: gatewayID,
				Consumer:  rc,
				Request:   &infracontext.RequestContext{Body: chatBody(tc.model)},
			})

			require.NoError(t, err)
			assert.Equal(t, 200, res.StatusCode)
			assert.Equal(t, []string{tc.want}, *invoked,
				"only the registry whose provider serves the model may be invoked")
		})
	}
}

func TestForward_SequentialChain_ProbesUnknownProvidersInConfiguredOrder(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	selfhosted := backendFor(gatewayID, "openai_compatible")
	vertex := backendFor(gatewayID, "vertex")
	rc := routableConsumerWith(gatewayID, selfhosted, vertex)

	listing := stubListing{verdicts: map[string]appcatalog.Verdict{
		"openai_compatible:gemini-3-flash-preview": appcatalog.VerdictUnknown,
		"vertex:gemini-3-flash-preview":            appcatalog.VerdictListed,
	}}

	invoker, invoked := invocationRecorder(t, func(provider string) (*appproxy.ProviderResponse, error) {
		if provider == "openai_compatible" {
			return &appproxy.ProviderResponse{StatusCode: 404, Body: modelNotFoundBody(provider)}, nil
		}
		return &appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil
	})
	fwd := newSequentialForwarder(t, invoker, listing)

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Body: chatBody("gemini-3-flash-preview")},
	})

	require.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, []string{"openai_compatible", "vertex"}, *invoked,
		"a provider with no authoritative listing keeps its configured position and is probed")
}

func TestForward_SequentialChain_NoRegistryServesTheModel(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	vertex := backendFor(gatewayID, "vertex")
	rc := routableConsumerWith(gatewayID, openai, vertex)

	invoker, invoked := invocationRecorder(t, func(provider string) (*appproxy.ProviderResponse, error) {
		return &appproxy.ProviderResponse{StatusCode: 404, Body: modelNotFoundBody(provider)}, nil
	})
	fwd := newSequentialForwarder(t, invoker, stubListing{})

	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Body: chatBody("nope-9")},
	})

	require.Error(t, err)
	assert.True(t, errors.Is(err, routingdomain.ErrNoRegistryServesModel),
		"the gateway must own the failure instead of relaying one provider's model_not_found, got %v", err)
	assert.Contains(t, err.Error(), "nope-9")
	assert.Contains(t, err.Error(), "registry-openai")
	assert.Contains(t, err.Error(), "registry-vertex")
	assert.NotContains(t, err.Error(), "tried",
		"the message names every bound registry, not the subset that was probed")
	assert.NotContains(t, err.Error(), "do not have access",
		"no provider's own text may reach the client")
	assert.Equal(t, []string{"openai", "vertex"}, *invoked)
}

func TestForward_SequentialChain_CatalogNeverIsTheSoleReasonToFail(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	vertex := backendFor(gatewayID, "vertex")
	rc := routableConsumerWith(gatewayID, openai, vertex)

	listing := stubListing{verdicts: map[string]appcatalog.Verdict{
		"openai:gpt-6-just-released": appcatalog.VerdictAbsent,
		"vertex:gpt-6-just-released": appcatalog.VerdictAbsent,
	}}

	invoker, invoked := invocationRecorder(t, func(provider string) (*appproxy.ProviderResponse, error) {
		if provider == "openai" {
			return &appproxy.ProviderResponse{StatusCode: 404, Body: modelNotFoundBody(provider)}, nil
		}
		return &appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil
	})
	fwd := newSequentialForwarder(t, invoker, listing)

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Body: chatBody("gpt-6-just-released")},
	})

	require.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, []string{"openai", "vertex"}, *invoked,
		"a model absent from every listing still gets the full chain probed, so a stale catalog cannot break it")
}

func TestForward_SequentialChain_QualifiedModelStaysPinned(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	vertex := backendFor(gatewayID, "vertex")
	rc := routableConsumerWith(gatewayID, openai, vertex)

	invoker, invoked := invocationRecorder(t, func(provider string) (*appproxy.ProviderResponse, error) {
		return &appproxy.ProviderResponse{StatusCode: 404, Body: modelNotFoundBody(provider)}, nil
	})
	fwd := newSequentialForwarder(t, invoker, stubListing{})

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Body: chatBody("@openai/whatever")},
	})

	require.NoError(t, err)
	assert.Equal(t, 404, res.StatusCode)
	assert.Equal(t, []string{"openai"}, *invoked,
		"a qualified reference is an operator override: it must not fall through to another registry")
}

func TestForward_SequentialChain_ExplicitAllowListStillDenies(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, openai)
	rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{
		openai.ID: {Allowed: []string{"gpt-4o-mini"}},
	}

	listing := stubListing{verdicts: map[string]appcatalog.Verdict{
		"openai:gpt-4.1": appcatalog.VerdictListed,
	}}

	invoker, invoked := invocationRecorder(t, func(string) (*appproxy.ProviderResponse, error) {
		return &appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil
	})
	fwd := newSequentialForwarder(t, invoker, listing)

	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Body: chatBody("gpt-4.1")},
	})

	require.Error(t, err)
	assert.True(t, errors.Is(err, routingdomain.ErrModelDenied),
		"an explicit allow-list keeps denying regardless of what the provider serves, got %v", err)
	assert.Empty(t, *invoked)
}

func TestForward_SequentialChain_UnqualifiedModelDoesNotLoadBalance(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	other := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, openai, other)

	listing := stubListing{verdicts: map[string]appcatalog.Verdict{
		"openai:gpt-4.1": appcatalog.VerdictListed,
	}}

	invoked := make([]ids.RegistryID, 0, 4)
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(
			_ context.Context,
			bk *registrydomain.Registry,
			_ *infracontext.RequestContext,
		) (*appproxy.ProviderResponse, error) {
			invoked = append(invoked, bk.ID)
			return &appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil
		}).
		Times(4)
	fwd := newSequentialForwarder(t, invoker, listing)

	for i := 0; i < 4; i++ {
		_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
			GatewayID: gatewayID,
			Consumer:  rc,
			Request:   &infracontext.RequestContext{Body: chatBody("gpt-4.1")},
		})
		require.NoError(t, err)
	}

	for _, got := range invoked {
		assert.Equal(t, openai.ID, got,
			"an unqualified model walks the chain deterministically; it must not be round-robined")
	}
}

func TestForward_SequentialChain_NilAvailabilityProbesEveryRegistry(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	vertex := backendFor(gatewayID, "vertex")
	rc := routableConsumerWith(gatewayID, openai, vertex)

	invoker, invoked := invocationRecorder(t, func(provider string) (*appproxy.ProviderResponse, error) {
		if provider == "openai" {
			return &appproxy.ProviderResponse{StatusCode: 404, Body: modelNotFoundBody(provider)}, nil
		}
		return &appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil
	})
	fwd := newSequentialForwarder(t, invoker, nil)

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Body: chatBody("gemini-3-flash-preview")},
	})

	require.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, []string{"openai", "vertex"}, *invoked)
}

func TestForward_SequentialChain_FallbackBudgetDoesNotTruncateRegistrySelection(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	vertex := backendFor(gatewayID, "vertex")
	rc := routableConsumerWith(gatewayID, openai, vertex)
	rc.Consumer.Fallback = &domainconsumer.Fallback{
		Enabled:  true,
		Triggers: []domainconsumer.FallbackTrigger{domainconsumer.TriggerHTTP5xx},
		Budget:   domainconsumer.FallbackBudget{MaxAttempts: 1},
	}

	invoker, invoked := invocationRecorder(t, func(provider string) (*appproxy.ProviderResponse, error) {
		if provider == "openai" {
			return &appproxy.ProviderResponse{StatusCode: 404, Body: modelNotFoundBody(provider)}, nil
		}
		return &appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil
	})
	fwd := newSequentialForwarder(t, invoker, stubListing{})

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Body: chatBody("gemini-3-flash-preview")},
	})

	require.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, []string{"openai", "vertex"}, *invoked,
		"the fallback attempt budget bounds failover retries, not registry selection")
}

func TestForward_SequentialChain_NoRegistryServesTheModelDropsTheProviderDetail(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, openai)

	invoker, _ := invocationRecorder(t, func(provider string) (*appproxy.ProviderResponse, error) {
		return &appproxy.ProviderResponse{StatusCode: 404, Body: modelNotFoundBody(provider)}, nil
	})
	fwd := newSequentialForwarder(t, invoker, stubListing{})

	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Body: chatBody("nope-9")},
	})

	require.Error(t, err)
	assert.True(t, errors.Is(err, routingdomain.ErrNoRegistryServesModel))
	assert.NotContains(t, err.Error(), "do not have access",
		"relaying the provider's own diagnosis sends the reader to debug the wrong system")
	assert.Contains(t, err.Error(), "registry-openai",
		"the gateway names the registry it ruled out, not the provider that answered")
}

func TestForward_SequentialChain_NoRegistryServesTheModelNamesEveryBoundRegistry(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	anthropic := backendFor(gatewayID, "anthropic")
	openai := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, anthropic, openai)
	rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{
		anthropic.ID: {Allowed: []string{"claude-haiku-*"}},
	}

	listing := stubListing{verdicts: map[string]appcatalog.Verdict{
		"openai:claude-sonnet-4-5": appcatalog.VerdictAbsent,
	}}

	invoker, invoked := invocationRecorder(t, func(provider string) (*appproxy.ProviderResponse, error) {
		return &appproxy.ProviderResponse{StatusCode: 404, Body: modelNotFoundBody(provider)}, nil
	})
	fwd := newSequentialForwarder(t, invoker, listing)

	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Body: chatBody("claude-sonnet-4-5")},
	})

	require.Error(t, err)
	assert.True(t, errors.Is(err, routingdomain.ErrNoRegistryServesModel))
	assert.Contains(t, err.Error(), `"claude-sonnet-4-5" (registry-anthropic: restricted by its `+
		`model allow-list; registry-openai: not in the provider catalog)`,
		"every bound registry is named with the reason it was ruled out")
	assert.Equal(t, []string{"openai"}, *invoked,
		"the allow-list rules anthropic out before any request is sent to it")
}

func TestForward_SequentialChain_NonShortIntentsIgnoreProviderAvailability(t *testing.T) {
	listing := stubListing{verdicts: map[string]appcatalog.Verdict{
		"openai:gpt-5": appcatalog.VerdictAbsent,
	}}

	t.Run("auto", func(t *testing.T) {
		gatewayID := ids.New[ids.GatewayKind]()
		openai := backendFor(gatewayID, "openai")
		rc := routableConsumerWith(gatewayID, openai)
		rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{
			openai.ID: {Allowed: []string{"gpt-5"}, Default: "gpt-5"},
		}

		invoker, invoked := invocationRecorder(t, func(string) (*appproxy.ProviderResponse, error) {
			return &appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil
		})
		fwd := newSequentialForwarder(t, invoker, listing)

		res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
			GatewayID: gatewayID,
			Consumer:  rc,
			Request:   &infracontext.RequestContext{Body: chatBody("auto")},
		})

		require.NoError(t, err)
		assert.Equal(t, 200, res.StatusCode)
		assert.Equal(t, []string{"openai"}, *invoked,
			"auto resolves against the consumer's default models, not the provider catalog")
	})

	t.Run("pool alias", func(t *testing.T) {
		gatewayID := ids.New[ids.GatewayKind]()
		openai := backendFor(gatewayID, "openai")
		rc := routableConsumerWith(gatewayID, openai)
		rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{
			openai.ID: {Allowed: []string{"gpt-5"}, Default: "gpt-5"},
		}
		rc.Consumer.LBConfig.Enabled = true
		rc.Consumer.LBConfig.PoolAlias = "fast-chat"
		rc.Consumer.LBConfig.Members = []domainconsumer.LBPoolMember{{RegistryID: openai.ID}}

		invoker, invoked := invocationRecorder(t, func(string) (*appproxy.ProviderResponse, error) {
			return &appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil
		})
		fwd := newSequentialForwarder(t, invoker, listing)

		res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
			GatewayID: gatewayID,
			Consumer:  rc,
			Request:   &infracontext.RequestContext{Body: []byte(`{"model":"pool:fast-chat"}`)},
		})

		require.NoError(t, err)
		assert.Equal(t, 200, res.StatusCode)
		assert.Equal(t, []string{"openai"}, *invoked,
			"a pool alias selects configured members, not by provider catalog")
	})
}

func TestForward_SequentialChain_RoleBasedConsumerSkipsRegistriesThatCannotServe(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	vertex := backendFor(gatewayID, "vertex")
	role := &roledomain.Role{
		ID:          ids.New[ids.RoleKind](),
		GatewayID:   gatewayID,
		Name:        "analyst",
		RegistryIDs: []ids.RegistryID{openai.ID, vertex.ID},
	}
	rc := &appconsumer.RoutableConsumer{
		Consumer: &domainconsumer.Consumer{
			ID:          ids.New[ids.ConsumerKind](),
			GatewayID:   gatewayID,
			RoutingMode: domainconsumer.RoutingModeRoleBased,
			RoleIDs:     []ids.RoleID{role.ID},
		},
	}
	data := appconsumer.NewData(gatewayID, nil, []*roledomain.Role{role})
	data.SetRegistryIndex(map[ids.RegistryID]*registrydomain.Registry{
		openai.ID: openai,
		vertex.ID: vertex,
	})

	listing := stubListing{verdicts: map[string]appcatalog.Verdict{
		"openai:gemini-3-flash-preview": appcatalog.VerdictAbsent,
		"vertex:gemini-3-flash-preview": appcatalog.VerdictListed,
	}}

	invoker, invoked := invocationRecorder(t, func(string) (*appproxy.ProviderResponse, error) {
		return &appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil
	})
	fwd := newSequentialForwarder(t, invoker, listing)

	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Data:      data,
		RoleIDs:   []ids.RoleID{role.ID},
		Request:   &infracontext.RequestContext{Body: chatBody("gemini-3-flash-preview")},
	})

	require.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, []string{"vertex"}, *invoked,
		"a role-based consumer must not be handed a registry whose provider cannot serve the model")
}
