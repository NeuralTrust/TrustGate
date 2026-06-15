package routing

import (
	"fmt"
	"strings"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
	routingdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/routing"
)

const (
	sourceConsumer = "consumer"
	sourceFallback = "fallback"
)

type RegistryLookup func(ids.RegistryID) (*registrydomain.Registry, bool)

type ResolveInput struct {
	Intent     routingdomain.Intent
	Consumer   *appconsumer.RoutableConsumer
	Roles      []*roledomain.Role
	Registries RegistryLookup
}

//go:generate mockery --name=Resolver --dir=. --output=./mocks --filename=routing_resolver_mock.go --case=underscore --with-expecter
type Resolver interface {
	Resolve(in ResolveInput) (*routingdomain.CandidateSet, error)
}

var _ Resolver = (*resolver)(nil)

type resolver struct{}

func NewResolver() Resolver {
	return &resolver{}
}

func (r *resolver) Resolve(in ResolveInput) (*routingdomain.CandidateSet, error) {
	if in.Consumer == nil || in.Consumer.Consumer == nil {
		return routingdomain.NewCandidateSet(), nil
	}
	if in.Consumer.Consumer.RoutingMode == consumerdomain.RoutingModeRoleBased {
		return r.resolveRoleBased(in)
	}
	return r.resolveInline(in)
}

func (r *resolver) resolveInline(in ResolveInput) (*routingdomain.CandidateSet, error) {
	if in.Intent.IsPool() {
		return r.resolveInlinePool(in)
	}
	base := routingdomain.NewCandidateSet()
	policies := in.Consumer.Consumer.ModelPolicies
	for _, reg := range in.Consumer.Registries {
		base.Add(inlineCandidate(reg, policies, sourceConsumer))
	}
	for _, reg := range in.Consumer.FallbackBackends {
		base.Add(inlineCandidate(reg, policies, sourceFallback))
	}
	return base.ResolveIntent(in.Intent)
}

func inlineCandidate(
	reg *registrydomain.Registry,
	policies consumerdomain.ModelPolicies,
	source string,
) routingdomain.Candidate {
	policy, ok := policies.For(reg.ID)
	if !ok {
		return routingdomain.Candidate{Registry: reg, Sources: []string{source}}
	}
	return routingdomain.Candidate{
		Registry: reg,
		Allowed:  policy.Allowed,
		Default:  policy.Default,
		Sources:  []string{source},
	}
}

func (r *resolver) resolveInlinePool(in ResolveInput) (*routingdomain.CandidateSet, error) {
	alias := in.Intent.PoolAlias
	lbCfg := in.Consumer.Consumer.LBConfig
	if lbCfg == nil || !lbCfg.Enabled || lbCfg.PoolAlias == "" || !strings.EqualFold(lbCfg.PoolAlias, alias) {
		return nil, fmt.Errorf("%w: pool %q is not configured for this consumer", routingdomain.ErrUnknownPoolAlias, alias)
	}
	byID := registriesByID(in.Consumer)
	policies := in.Consumer.Consumer.ModelPolicies
	out := routingdomain.NewCandidateSet()
	for _, member := range lbCfg.Members {
		reg, ok := byID[member.RegistryID]
		if !ok {
			continue
		}
		policy, _ := policies.For(reg.ID)
		out.Add(routingdomain.Candidate{
			Registry: reg,
			Allowed:  memberAllowed(member, policy),
			Default:  memberDefault(member, policy),
			Sources:  []string{"pool:" + alias},
		})
	}
	if out.Len() == 0 {
		return nil, fmt.Errorf("%w: pool %q has no resolvable members", routingdomain.ErrModelDenied, alias)
	}
	return out, nil
}

func registriesByID(rc *appconsumer.RoutableConsumer) map[ids.RegistryID]*registrydomain.Registry {
	byID := make(map[ids.RegistryID]*registrydomain.Registry, len(rc.Registries)+len(rc.FallbackBackends))
	for _, reg := range rc.Registries {
		byID[reg.ID] = reg
	}
	for _, reg := range rc.FallbackBackends {
		byID[reg.ID] = reg
	}
	return byID
}

func memberAllowed(member consumerdomain.LBPoolMember, policy consumerdomain.ModelPolicy) []string {
	if len(member.Models) > 0 {
		return member.Models
	}
	return policy.Allowed
}

func memberDefault(member consumerdomain.LBPoolMember, policy consumerdomain.ModelPolicy) string {
	if len(member.Models) == 0 {
		return policy.Default
	}
	for _, model := range member.Models {
		if model == policy.Default {
			return policy.Default
		}
	}
	return member.Models[0]
}

func (r *resolver) resolveRoleBased(in ResolveInput) (*routingdomain.CandidateSet, error) {
	if in.Intent.IsPool() {
		return nil, fmt.Errorf(
			"%w: pool %q (pool aliases are not available for role-based consumers)",
			routingdomain.ErrUnknownPoolAlias, in.Intent.PoolAlias,
		)
	}
	base := routingdomain.NewCandidateSet()
	for _, role := range in.Roles {
		if role == nil {
			continue
		}
		for _, registryID := range role.RegistryIDs {
			reg, ok := lookupRegistry(in.Registries, registryID)
			if !ok {
				continue
			}
			policy := role.ModelPolicies[registryID]
			base.Add(routingdomain.Candidate{
				Registry: reg,
				Allowed:  policy.Allowed,
				Default:  policy.Default,
				Sources:  []string{"role:" + role.Name},
			})
		}
	}
	if base.Len() == 0 {
		return base, nil
	}
	return base.ResolveIntent(in.Intent)
}

func lookupRegistry(lookup RegistryLookup, id ids.RegistryID) (*registrydomain.Registry, bool) {
	if lookup == nil {
		return nil, false
	}
	return lookup(id)
}
