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

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/mock"
)

func TestForward_QualifiedIntentRestrictsPoolAndRewritesModel(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	anthropic := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, openai, anthropic)

	var invokedBody []byte
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool {
			return bk.ID == openai.ID
		}), mock.Anything).
		Run(func(_ context.Context, _ *registrydomain.Registry, req *infracontext.RequestContext) {
			invokedBody = req.Body
		}).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request: &infracontext.RequestContext{
			Context: context.Background(),
			Body:    []byte(`{"model":"@openai/gpt-5"}`),
		},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	if string(invokedBody) != `{"model":"gpt-5"}` {
		t.Fatalf("expected native model rewrite, got %s", invokedBody)
	}
}

func TestForward_QualifiedIntentDeniedByPolicy(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, openai)
	rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{
		openai.ID: {Allowed: []string{"gpt-5"}},
	}

	fwd := newTestForwarder(t, proxymocks.NewProviderInvoker(t))
	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request: &infracontext.RequestContext{
			Context: context.Background(),
			Body:    []byte(`{"model":"@openai/gpt-4o"}`),
		},
	})
	if !errors.Is(err, routingdomain.ErrModelDenied) {
		t.Fatalf("expected ErrModelDenied, got %v", err)
	}
}

func TestForward_UnknownPoolAlias(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, openai)

	fwd := newTestForwarder(t, proxymocks.NewProviderInvoker(t))
	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request: &infracontext.RequestContext{
			Context: context.Background(),
			Body:    []byte(`{"model":"pool:missing"}`),
		},
	})
	if !errors.Is(err, routingdomain.ErrUnknownPoolAlias) {
		t.Fatalf("expected ErrUnknownPoolAlias, got %v", err)
	}
}

func TestForward_PoolAliasRoutesToMembersOnly(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	member := backendFor(gatewayID, "openai")
	outside := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, member, outside)
	rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{
		member.ID:  {Allowed: []string{"gpt-5"}, Default: "gpt-5"},
		outside.ID: {Allowed: []string{"claude-4"}, Default: "claude-4"},
	}
	rc.Consumer.LBConfig.Enabled = true
	rc.Consumer.LBConfig.PoolAlias = "fast-chat"
	rc.Consumer.LBConfig.Members = []domainconsumer.LBPoolMember{{RegistryID: member.ID}}

	var invokedReq *infracontext.RequestContext
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool {
			return bk.ID == member.ID
		}), mock.Anything).
		Run(func(_ context.Context, _ *registrydomain.Registry, req *infracontext.RequestContext) {
			invokedReq = req
		}).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request: &infracontext.RequestContext{
			Context: context.Background(),
			Body:    []byte(`{"model":"pool:fast-chat"}`),
		},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	if string(invokedReq.Body) != `{}` {
		t.Fatalf("expected pool ref stripped from body, got %s", invokedReq.Body)
	}
	if invokedReq.DefaultModel != "gpt-5" {
		t.Fatalf("expected member default stamped, got %q", invokedReq.DefaultModel)
	}
}

func TestForward_RoleBasedPicksDirectly(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	role := &roledomain.Role{
		ID:            ids.New[ids.RoleKind](),
		GatewayID:     gatewayID,
		Name:          "analyst",
		RegistryIDs:   []ids.RegistryID{openai.ID},
		ModelPolicies: roledomain.ModelPolicies{openai.ID: {Allowed: []string{"gpt-5"}, Default: "gpt-5"}},
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
	data.SetRegistryIndex(map[ids.RegistryID]*registrydomain.Registry{openai.ID: openai})

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool {
			return bk.ID == openai.ID
		}), mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Data:      data,
		RoleIDs:   []ids.RoleID{role.ID},
		Request: &infracontext.RequestContext{
			Context: context.Background(),
			Body:    []byte(`{"model":"gpt-5"}`),
		},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
}

func TestForward_RoleBasedDeniedModel(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	role := &roledomain.Role{
		ID:            ids.New[ids.RoleKind](),
		GatewayID:     gatewayID,
		Name:          "analyst",
		RegistryIDs:   []ids.RegistryID{openai.ID},
		ModelPolicies: roledomain.ModelPolicies{openai.ID: {Allowed: []string{"gpt-5"}}},
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
	data.SetRegistryIndex(map[ids.RegistryID]*registrydomain.Registry{openai.ID: openai})

	fwd := newTestForwarder(t, proxymocks.NewProviderInvoker(t))
	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Data:      data,
		RoleIDs:   []ids.RoleID{role.ID},
		Request: &infracontext.RequestContext{
			Context: context.Background(),
			Body:    []byte(`{"model":"@openai/gpt-4o"}`),
		},
	})
	if !errors.Is(err, routingdomain.ErrModelDenied) {
		t.Fatalf("expected ErrModelDenied, got %v", err)
	}
}

func TestForward_RoleBasedWithoutRolesIs503(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := &appconsumer.RoutableConsumer{
		Consumer: &domainconsumer.Consumer{
			ID:          ids.New[ids.ConsumerKind](),
			GatewayID:   gatewayID,
			RoutingMode: domainconsumer.RoutingModeRoleBased,
		},
	}

	fwd := newTestForwarder(t, proxymocks.NewProviderInvoker(t))
	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Context: context.Background()},
	})
	if !errors.Is(err, appproxy.ErrNoBackendsInPool) {
		t.Fatalf("expected ErrNoBackendsInPool, got %v", err)
	}
}

func TestForward_ShortModelAmbiguousAcrossProviders(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	azure := backendFor(gatewayID, "azure")
	rc := routableConsumerWith(gatewayID, openai, azure)
	rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{
		openai.ID: {Allowed: []string{"gpt-5"}},
		azure.ID:  {Allowed: []string{"gpt-5"}},
	}

	fwd := newTestForwarder(t, proxymocks.NewProviderInvoker(t))
	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request: &infracontext.RequestContext{
			Context: context.Background(),
			Body:    []byte(`{"model":"gpt-5"}`),
		},
	})
	if !errors.Is(err, routingdomain.ErrAmbiguousModel) {
		t.Fatalf("expected ErrAmbiguousModel, got %v", err)
	}
}

func TestForward_ShortModelSingleProviderKeepsBalancing(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	a := backendFor(gatewayID, "openai")
	b := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, a, b)
	rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{
		a.ID: {Allowed: []string{"gpt-5"}},
		b.ID: {Allowed: []string{"gpt-5"}},
	}

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request: &infracontext.RequestContext{
			Context: context.Background(),
			Body:    []byte(`{"model":"gpt-5"}`),
		},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
}

func TestForward_PoolAliasBalancesAcrossMembers(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	memberA := backendFor(gatewayID, "openai")
	memberB := backendFor(gatewayID, "openai")
	outside := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, memberA, memberB, outside)
	rc.Consumer.LBConfig.Enabled = true
	rc.Consumer.LBConfig.PoolAlias = "fast-chat"
	rc.Consumer.LBConfig.Members = []domainconsumer.LBPoolMember{
		{RegistryID: memberA.ID},
		{RegistryID: memberB.ID},
	}

	invoked := make(map[ids.RegistryID]int)
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, bk *registrydomain.Registry, _ *infracontext.RequestContext) {
			invoked[bk.ID]++
		}).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Times(4)

	fwd := newTestForwarder(t, invoker)
	for i := 0; i < 4; i++ {
		_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
			GatewayID: gatewayID,
			Consumer:  rc,
			Request: &infracontext.RequestContext{
				Context: context.Background(),
				Body:    []byte(`{"model":"pool:fast-chat"}`),
			},
		})
		if err != nil {
			t.Fatalf("Forward %d: %v", i, err)
		}
	}
	if invoked[outside.ID] != 0 {
		t.Fatalf("non-member registry must never be selected, got %d invocations", invoked[outside.ID])
	}
	if invoked[memberA.ID] != 2 || invoked[memberB.ID] != 2 {
		t.Fatalf("expected round-robin 2/2 across pool members, got %d/%d", invoked[memberA.ID], invoked[memberB.ID])
	}
}

func TestForward_RoleBasedNeverEntersLBOrFallback(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	fallbackBk := backendFor(gatewayID, "anthropic")
	role := &roledomain.Role{
		ID:            ids.New[ids.RoleKind](),
		GatewayID:     gatewayID,
		Name:          "analyst",
		RegistryIDs:   []ids.RegistryID{openai.ID},
		ModelPolicies: roledomain.ModelPolicies{openai.ID: {Allowed: []string{"gpt-5"}, Default: "gpt-5"}},
	}
	rc := &appconsumer.RoutableConsumer{
		Consumer: &domainconsumer.Consumer{
			ID:          ids.New[ids.ConsumerKind](),
			GatewayID:   gatewayID,
			RoutingMode: domainconsumer.RoutingModeRoleBased,
			RoleIDs:     []ids.RoleID{role.ID},
			Fallback:    enabledFallback(fallbackBk.ID),
		},
		FallbackBackends: []*registrydomain.Registry{fallbackBk},
	}
	data := appconsumer.NewData(gatewayID, nil, []*roledomain.Role{role})
	data.SetRegistryIndex(map[ids.RegistryID]*registrydomain.Registry{
		openai.ID:     openai,
		fallbackBk.ID: fallbackBk,
	})

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool {
			return bk.ID == openai.ID
		}), mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 503, Body: []byte("down")}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Data:      data,
		RoleIDs:   []ids.RoleID{role.ID},
		Request: &infracontext.RequestContext{
			Context: context.Background(),
			Body:    []byte(`{"model":"gpt-5"}`),
		},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 503 {
		t.Fatalf("expected 503 relayed without fallback, got %d", res.StatusCode)
	}
}

func TestForward_SpanRecordsRouteSource(t *testing.T) {
	cases := []struct {
		name  string
		setup func(gatewayID ids.GatewayID, bk *registrydomain.Registry) (appproxy.ForwardInput, string)
	}{
		{
			name: "pool alias",
			setup: func(gatewayID ids.GatewayID, bk *registrydomain.Registry) (appproxy.ForwardInput, string) {
				rc := routableConsumerWith(gatewayID, bk)
				rc.Consumer.LBConfig.Enabled = true
				rc.Consumer.LBConfig.PoolAlias = "fast-chat"
				rc.Consumer.LBConfig.Members = []domainconsumer.LBPoolMember{{RegistryID: bk.ID}}
				return appproxy.ForwardInput{
					GatewayID: gatewayID,
					Consumer:  rc,
					Request:   &infracontext.RequestContext{Body: []byte(`{"model":"pool:fast-chat"}`)},
				}, "pool:fast-chat"
			},
		},
		{
			name: "role based",
			setup: func(gatewayID ids.GatewayID, bk *registrydomain.Registry) (appproxy.ForwardInput, string) {
				role := &roledomain.Role{
					ID:            ids.New[ids.RoleKind](),
					GatewayID:     gatewayID,
					Name:          "analyst",
					RegistryIDs:   []ids.RegistryID{bk.ID},
					ModelPolicies: roledomain.ModelPolicies{bk.ID: {Allowed: []string{"gpt-5"}, Default: "gpt-5"}},
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
				data.SetRegistryIndex(map[ids.RegistryID]*registrydomain.Registry{bk.ID: bk})
				return appproxy.ForwardInput{
					GatewayID: gatewayID,
					Consumer:  rc,
					Data:      data,
					RoleIDs:   []ids.RoleID{role.ID},
					Request:   &infracontext.RequestContext{Body: []byte(`{"model":"gpt-5"}`)},
				}, "role:analyst"
			},
		},
		{
			name: "inline passthrough",
			setup: func(gatewayID ids.GatewayID, bk *registrydomain.Registry) (appproxy.ForwardInput, string) {
				rc := routableConsumerWith(gatewayID, bk)
				return appproxy.ForwardInput{
					GatewayID: gatewayID,
					Consumer:  rc,
					Request:   &infracontext.RequestContext{Body: []byte(`{}`)},
				}, "consumer"
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gatewayID := ids.New[ids.GatewayKind]()
			bk := backendFor(gatewayID, "openai")
			in, wantRoute := tc.setup(gatewayID, bk)

			invoker := proxymocks.NewProviderInvoker(t)
			invoker.EXPECT().
				Invoke(mock.Anything, mock.Anything, mock.Anything).
				Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
				Once()

			fwd := newTestForwarder(t, invoker)
			rt := trace.New("trace-route", trace.Metadata{})
			ctx := trace.NewContext(context.Background(), rt)
			in.Request.Context = ctx

			_, err := fwd.Forward(ctx, in)
			if err != nil {
				t.Fatalf("Forward: %v", err)
			}
			spans := rt.Spans()
			if len(spans) != 1 || spans[0].LLM == nil {
				t.Fatalf("expected one LLM span, got %d", len(spans))
			}
			if spans[0].LLM.Route != wantRoute {
				t.Fatalf("expected route %q, got %q", wantRoute, spans[0].LLM.Route)
			}
		})
	}
}

func TestForward_ClientSuppliedModelIDIsRejected(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bedrock := backendFor(gatewayID, "bedrock")
	rc := routableConsumerWith(gatewayID, bedrock)

	const arn = `arn:aws:bedrock:eu-west-1:123456789012:inference-profile/eu.anthropic.claude-sonnet-4-v1:0`
	body := []byte(`{"modelId":"` + arn + `","messages":[]}`)

	invoker := proxymocks.NewProviderInvoker(t)

	fwd := newTestForwarder(t, invoker)
	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request: &infracontext.RequestContext{
			Context: context.Background(),
			Body:    body,
		},
	})
	if !errors.Is(err, routingdomain.ErrInvalidModelRef) {
		t.Fatalf("expected ErrInvalidModelRef for client-supplied modelId, got %v", err)
	}
}

func TestForward_ArnInModelFieldStaysNative(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bedrock := backendFor(gatewayID, "bedrock")
	rc := routableConsumerWith(gatewayID, bedrock)

	const arn = `arn:aws:bedrock:eu-west-1:123456789012:inference-profile/eu.anthropic.claude-sonnet-4-v1:0`
	rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{
		bedrock.ID: {Allowed: []string{arn}},
	}

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok")}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)
	res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request: &infracontext.RequestContext{
			Context: context.Background(),
			Body:    []byte(`{"model":"` + arn + `","messages":[]}`),
		},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
}

func TestForward_SpanRecordsRequestedModel(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, openai)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: 200, Body: []byte("ok"), Model: "gpt-5"}, nil).
		Once()

	fwd := newTestForwarder(t, invoker)
	rt := trace.New("trace-requested", trace.Metadata{})
	ctx := trace.NewContext(context.Background(), rt)

	_, err := fwd.Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request: &infracontext.RequestContext{
			Context: ctx,
			Body:    []byte(`{"model":"@openai/gpt-5"}`),
		},
	})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	spans := rt.Spans()
	if len(spans) != 1 || spans[0].LLM == nil {
		t.Fatalf("expected one LLM span, got %d", len(spans))
	}
	if spans[0].LLM.RequestedModel != "@openai/gpt-5" {
		t.Fatalf("expected original requested model, got %q", spans[0].LLM.RequestedModel)
	}
	if spans[0].LLM.Model != "gpt-5" {
		t.Fatalf("expected final native model, got %q", spans[0].LLM.Model)
	}
}

func TestForward_InvalidModelRef(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, openai)

	fwd := newTestForwarder(t, proxymocks.NewProviderInvoker(t))
	_, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request: &infracontext.RequestContext{
			Context: context.Background(),
			Body:    []byte(`{"model":"pool:"}`),
		},
	})
	if !errors.Is(err, routingdomain.ErrInvalidModelRef) {
		t.Fatalf("expected ErrInvalidModelRef, got %v", err)
	}
}
