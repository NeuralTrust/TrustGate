package proxy

import (
	"fmt"
	"strings"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	approuting "github.com/NeuralTrust/AgentGateway/pkg/app/routing"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
	routingdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/routing"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
)

type routedBackend struct {
	lb           *loadbalancer.LoadBalancer
	backend      *domain.Registry
	excluded     map[ids.RegistryID]struct{}
	fromFallback bool
}

func (f *forwarder) resolveRouting(in ForwardInput) (routingdomain.RoutingIntent, *routingdomain.CandidateSet, error) {
	intent, ref, err := parseIntent(in.Request)
	if err != nil {
		return intent, nil, err
	}
	in.Request.RequestedModel = ref
	if intent.IsZero() && !isRoleBased(in.Consumer) {
		return intent, nil, nil
	}
	candidates, err := f.resolver.Resolve(approuting.ResolveInput{
		Intent:     intent,
		Consumer:   in.Consumer,
		Roles:      effectiveRoles(in.Data, in.RoleIDs),
		Registries: registryLookup(in.Data),
	})
	if err != nil {
		return intent, nil, err
	}
	if candidates.Len() == 0 {
		return intent, nil, ErrNoBackendsInPool
	}
	return intent, candidates, nil
}

func isRoleBased(rc *appconsumer.RoutableConsumer) bool {
	return rc.Consumer.RoutingMode == consumerdomain.RoutingModeRoleBased
}

func parseIntent(req *infracontext.RequestContext) (routingdomain.RoutingIntent, string, error) {
	if req == nil || len(req.Body) == 0 {
		return routingdomain.RoutingIntent{}, "", nil
	}
	ref, hasModelID, err := adapter.ExtractModelField(req.Body)
	if err != nil {
		return routingdomain.RoutingIntent{}, "", nil
	}
	if hasModelID {
		return routingdomain.RoutingIntent{}, "", fmt.Errorf(
			"%w: modelId is not universal payload syntax, use the model field", routingdomain.ErrInvalidModelRef)
	}
	intent, err := routingdomain.ParseModelRef(ref)
	return intent, strings.TrimSpace(ref), err
}

func applyIntentToBody(req *infracontext.RequestContext, intent routingdomain.RoutingIntent) {
	if req == nil || intent.IsZero() {
		return
	}
	if intent.IsPool() {
		req.Body = adapter.StripModel(req.Body)
		return
	}
	if intent.IsQualified() {
		req.Body = adapter.OverrideModel(req.Body, intent.Model)
	}
}

func effectiveRoles(data *appconsumer.Data, roleIDs []ids.RoleID) []*roledomain.Role {
	if data == nil || len(roleIDs) == 0 {
		return nil
	}
	want := make(map[ids.RoleID]struct{}, len(roleIDs))
	for _, id := range roleIDs {
		want[id] = struct{}{}
	}
	out := make([]*roledomain.Role, 0, len(roleIDs))
	for _, r := range data.Roles {
		if r == nil {
			continue
		}
		if _, ok := want[r.ID]; ok {
			out = append(out, r)
		}
	}
	return out
}

func registryLookup(data *appconsumer.Data) approuting.RegistryLookup {
	if data == nil {
		return nil
	}
	return data.RegistryByID
}

func (f *forwarder) routeBackend(
	rc *appconsumer.RoutableConsumer,
	req *infracontext.RequestContext,
	intent routingdomain.RoutingIntent,
	candidates *routingdomain.CandidateSet,
) (routedBackend, error) {
	if isRoleBased(rc) {
		return routedBackend{
			backend:  candidates.Candidates()[0].Registry,
			excluded: make(map[ids.RegistryID]struct{}),
		}, nil
	}
	if len(rc.Registries) == 0 {
		return routedBackend{}, ErrNoBackendsInPool
	}
	lb, err := f.routeLoadBalancer(rc, intent, candidates)
	if err != nil {
		return routedBackend{}, err
	}
	excluded := nonCandidateRegistries(rc, candidates)
	bk, err := lb.NextBackend(req, excluded)
	if err != nil {
		if fallback := firstAvailableFallback(rc, excluded); fallback != nil {
			return routedBackend{lb: lb, backend: fallback, excluded: excluded, fromFallback: true}, nil
		}
		return routedBackend{}, fmt.Errorf("%w: %s", ErrNoBackendAvailable, err.Error())
	}
	return routedBackend{lb: lb, backend: bk, excluded: excluded}, nil
}

func (f *forwarder) routeLoadBalancer(
	rc *appconsumer.RoutableConsumer,
	intent routingdomain.RoutingIntent,
	candidates *routingdomain.CandidateSet,
) (*loadbalancer.LoadBalancer, error) {
	if intent.IsPool() {
		return f.poolLoadBalancerFor(rc, intent.PoolAlias, candidates)
	}
	return f.loadBalancerFor(rc)
}

func nonCandidateRegistries(
	rc *appconsumer.RoutableConsumer,
	candidates *routingdomain.CandidateSet,
) map[ids.RegistryID]struct{} {
	excluded := make(map[ids.RegistryID]struct{})
	if candidates == nil {
		return excluded
	}
	for _, reg := range rc.Registries {
		if !candidates.HasRegistry(reg.ID) {
			excluded[reg.ID] = struct{}{}
		}
	}
	for _, reg := range rc.FallbackBackends {
		if !candidates.HasRegistry(reg.ID) {
			excluded[reg.ID] = struct{}{}
		}
	}
	return excluded
}

func firstAvailableFallback(
	rc *appconsumer.RoutableConsumer,
	excluded map[ids.RegistryID]struct{},
) *domain.Registry {
	if fb := rc.Consumer.Fallback; fb == nil || !fb.Enabled {
		return nil
	}
	for _, bk := range rc.FallbackBackends {
		if _, skip := excluded[bk.ID]; !skip {
			return bk
		}
	}
	return nil
}

func (f *forwarder) stampRoutingPolicy(dto *forwardRequestDTO, rc *appconsumer.RoutableConsumer, bk *domain.Registry) {
	dto.routeSource = routeSourceFor(dto.candidates, bk)
	if candidate, ok := dto.candidates.ForRegistry(bk.ID); ok {
		dto.request.AllowedModels = candidate.Allowed
		dto.request.DefaultModel = candidate.Default
		return
	}
	policy, ok := rc.Consumer.ModelPolicies.For(bk.ID)
	if !ok {
		dto.request.AllowedModels = nil
		dto.request.DefaultModel = ""
		return
	}
	dto.request.AllowedModels = policy.Allowed
	dto.request.DefaultModel = policy.Default
}

func routeSourceFor(candidates *routingdomain.CandidateSet, bk *domain.Registry) string {
	if candidate, ok := candidates.ForRegistry(bk.ID); ok && len(candidate.Sources) > 0 {
		return strings.Join(candidate.Sources, ",")
	}
	return "consumer"
}
