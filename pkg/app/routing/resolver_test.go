package routing_test

import (
	"errors"
	"testing"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	approuting "github.com/NeuralTrust/AgentGateway/pkg/app/routing"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
	routingdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/routing"
)

func newRegistry(provider string) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		Type:      registrydomain.TypeLLM,
		LLMTarget: &registrydomain.LLMTarget{Provider: provider},
	}
}

func inlineConsumer(registries []*registrydomain.Registry, policies consumerdomain.ModelPolicies, lb *consumerdomain.LBConfig) *appconsumer.RoutableConsumer {
	return &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:            ids.New[ids.ConsumerKind](),
			RoutingMode:   consumerdomain.RoutingModeInline,
			ModelPolicies: policies,
			LBConfig:      lb,
		},
		Registries: registries,
	}
}

func roleBasedConsumer() *appconsumer.RoutableConsumer {
	return &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:          ids.New[ids.ConsumerKind](),
			RoutingMode: consumerdomain.RoutingModeRoleBased,
		},
	}
}

func lookupFor(registries ...*registrydomain.Registry) approuting.RegistryLookup {
	byID := make(map[ids.RegistryID]*registrydomain.Registry, len(registries))
	for _, reg := range registries {
		byID[reg.ID] = reg
	}
	return func(id ids.RegistryID) (*registrydomain.Registry, bool) {
		reg, ok := byID[id]
		return reg, ok
	}
}

func TestResolver_InlineZeroIntentIncludesPoolAndFallback(t *testing.T) {
	t.Parallel()
	pool := newRegistry("openai")
	fallback := newRegistry("anthropic")
	rc := inlineConsumer([]*registrydomain.Registry{pool}, nil, nil)
	rc.FallbackBackends = []*registrydomain.Registry{fallback}

	cs, err := approuting.NewResolver().Resolve(approuting.ResolveInput{Consumer: rc})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cs.Len() != 2 || !cs.HasRegistry(pool.ID) || !cs.HasRegistry(fallback.ID) {
		t.Fatalf("expected pool and fallback candidates, got %d", cs.Len())
	}
}

func TestResolver_InlineQualifiedHonorsPolicies(t *testing.T) {
	t.Parallel()
	openai := newRegistry("openai")
	azure := newRegistry("azure")
	policies := consumerdomain.ModelPolicies{
		openai.ID: {Allowed: []string{"gpt-5"}},
		azure.ID:  {Allowed: []string{"gpt-4o"}},
	}
	rc := inlineConsumer([]*registrydomain.Registry{openai, azure}, policies, nil)

	cs, err := approuting.NewResolver().Resolve(approuting.ResolveInput{
		Intent:   routingdomain.Intent{Provider: "openai", Model: "gpt-5"},
		Consumer: rc,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cs.Len() != 1 || !cs.HasRegistry(openai.ID) {
		t.Fatalf("expected single openai candidate, got %d", cs.Len())
	}

	_, err = approuting.NewResolver().Resolve(approuting.ResolveInput{
		Intent:   routingdomain.Intent{Provider: "azure", Model: "gpt-5"},
		Consumer: rc,
	})
	if !errors.Is(err, routingdomain.ErrModelDenied) {
		t.Fatalf("expected ErrModelDenied, got %v", err)
	}
}

func TestResolver_InlinePoolAlias(t *testing.T) {
	t.Parallel()
	a := newRegistry("openai")
	b := newRegistry("openai")
	c := newRegistry("anthropic")
	policies := consumerdomain.ModelPolicies{
		a.ID: {Allowed: []string{"gpt-5", "gpt-5-mini"}, Default: "gpt-5"},
		b.ID: {Allowed: []string{"gpt-5"}},
		c.ID: {Allowed: []string{"claude-4"}},
	}
	lb := &consumerdomain.LBConfig{
		Enabled:   true,
		PoolAlias: "fast-chat",
		Members: []consumerdomain.LBPoolMember{
			{RegistryID: a.ID, Models: []string{"gpt-5-mini"}},
			{RegistryID: b.ID},
		},
	}
	rc := inlineConsumer([]*registrydomain.Registry{a, b, c}, policies, lb)

	cs, err := approuting.NewResolver().Resolve(approuting.ResolveInput{
		Intent:   routingdomain.Intent{PoolAlias: "fast-chat"},
		Consumer: rc,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cs.Len() != 2 || cs.HasRegistry(c.ID) {
		t.Fatalf("expected only pool members, got %d", cs.Len())
	}
	memberA, _ := cs.ForRegistry(a.ID)
	if memberA.Default != "gpt-5-mini" || len(memberA.Allowed) != 1 {
		t.Fatalf("member models must narrow the candidate, got %+v", memberA)
	}
	memberB, _ := cs.ForRegistry(b.ID)
	if memberB.Default != "" || len(memberB.Allowed) != 1 {
		t.Fatalf("member without models must inherit policy, got %+v", memberB)
	}
}

func TestResolver_InlineUnknownPoolAlias(t *testing.T) {
	t.Parallel()
	reg := newRegistry("openai")
	rc := inlineConsumer([]*registrydomain.Registry{reg}, nil, nil)

	_, err := approuting.NewResolver().Resolve(approuting.ResolveInput{
		Intent:   routingdomain.Intent{PoolAlias: "missing"},
		Consumer: rc,
	})
	if !errors.Is(err, routingdomain.ErrUnknownPoolAlias) {
		t.Fatalf("expected ErrUnknownPoolAlias, got %v", err)
	}
}

func TestResolver_RoleBasedMergesRoles(t *testing.T) {
	t.Parallel()
	openai := newRegistry("openai")
	anthropic := newRegistry("anthropic")
	roleA := &roledomain.Role{
		Name:          "analyst",
		RegistryIDs:   []ids.RegistryID{openai.ID},
		ModelPolicies: roledomain.ModelPolicies{openai.ID: {Allowed: []string{"gpt-5"}}},
	}
	roleB := &roledomain.Role{
		Name:          "writer",
		RegistryIDs:   []ids.RegistryID{openai.ID, anthropic.ID},
		ModelPolicies: roledomain.ModelPolicies{openai.ID: {Allowed: []string{"gpt-5-mini"}}, anthropic.ID: {Allowed: []string{"claude-4"}}},
	}

	cs, err := approuting.NewResolver().Resolve(approuting.ResolveInput{
		Consumer:   roleBasedConsumer(),
		Roles:      []*roledomain.Role{roleA, roleB},
		Registries: lookupFor(openai, anthropic),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cs.Len() != 2 {
		t.Fatalf("expected merged candidates, got %d", cs.Len())
	}
	merged, _ := cs.ForRegistry(openai.ID)
	if len(merged.Allowed) != 2 {
		t.Fatalf("expected union of role allow-lists, got %v", merged.Allowed)
	}
	if len(merged.Sources) != 2 {
		t.Fatalf("expected provenance from both roles, got %v", merged.Sources)
	}
}

func TestResolver_RoleBasedDeniedOutsideRoles(t *testing.T) {
	t.Parallel()
	openai := newRegistry("openai")
	role := &roledomain.Role{
		Name:          "analyst",
		RegistryIDs:   []ids.RegistryID{openai.ID},
		ModelPolicies: roledomain.ModelPolicies{openai.ID: {Allowed: []string{"gpt-5"}}},
	}

	_, err := approuting.NewResolver().Resolve(approuting.ResolveInput{
		Intent:     routingdomain.Intent{Provider: "openai", Model: "gpt-4o"},
		Consumer:   roleBasedConsumer(),
		Roles:      []*roledomain.Role{role},
		Registries: lookupFor(openai),
	})
	if !errors.Is(err, routingdomain.ErrModelDenied) {
		t.Fatalf("expected ErrModelDenied, got %v", err)
	}
}

func TestResolver_RoleBasedRejectsPoolAlias(t *testing.T) {
	t.Parallel()
	_, err := approuting.NewResolver().Resolve(approuting.ResolveInput{
		Intent:   routingdomain.Intent{PoolAlias: "fast"},
		Consumer: roleBasedConsumer(),
	})
	if !errors.Is(err, routingdomain.ErrUnknownPoolAlias) {
		t.Fatalf("expected ErrUnknownPoolAlias, got %v", err)
	}
}

func TestResolver_RoleBasedNoRolesYieldsEmptySet(t *testing.T) {
	t.Parallel()
	cs, err := approuting.NewResolver().Resolve(approuting.ResolveInput{Consumer: roleBasedConsumer()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cs.Len() != 0 {
		t.Fatalf("expected empty set, got %d", cs.Len())
	}
}
