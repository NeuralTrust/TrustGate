package proxy_test

import (
	"context"
	"errors"
	"testing"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	appproxy "github.com/NeuralTrust/AgentGateway/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/AgentGateway/pkg/app/proxy/mocks"
	domainconsumer "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
	routingdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/routing"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
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
			Body:    []byte(`{"model":"openai/gpt-5"}`),
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
			Body:    []byte(`{"model":"openai/gpt-4o"}`),
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
			Body:    []byte(`{"model":"openai/gpt-4o"}`),
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
